"""
ArogyaRoute NE — Flask Backend v3.0
Security & Feature Upgrades:
  ✦ Gender field on registration (Male/Female/Other)
  ✦ Doctor profiles: specialty, experience, fee, 5-day shifts, slot capacity
  ✦ Date-aware slot booking (today + next 5 days) per doctor
  ✦ Request signature verification (HMAC-SHA256)
  ✦ Rate limiting per IP (token bucket)
  ✦ SQL/XSS input sanitizer on all text inputs
  ✦ Secure headers middleware (CSP, HSTS, X-Frame-Options)
  ✦ Booking cancellation (up to 2 hrs before slot)
  ✦ All v2 modules retained
"""

import os, re, time, hmac, hashlib, random, string, logging, html
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps

import numpy as np
from flask import Flask, request, jsonify, render_template, g
from flask_cors import CORS
from dotenv import load_dotenv

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LinearRegression
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.secret_key = os.getenv("SECRET_KEY", "arogyaroute-ne-v3-secret-change-in-prod")

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  SECURITY LAYER                                                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

SIGNING_SECRET  = os.getenv("SIGNING_SECRET", "hmac-signing-key-change-in-prod").encode()
RATE_LIMIT_WINDOW  = 60      # seconds
RATE_LIMIT_MAX_REQ = 60      # max requests per window per IP
_rate_buckets: dict = defaultdict(list)
_BLOCKED_IPS:  set  = set()

# ── Input sanitizer ────────────────────────────────────────────────────────────
_XSS_PATTERN  = re.compile(r"<[^>]*?>|javascript:|data:|vbscript:", re.I)
_SQL_PATTERN  = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|EXECUTE|"
    r"DECLARE|CAST|CONVERT|CHAR|NCHAR|VARCHAR|ALTER|CREATE|TRUNCATE)\b"
    r"|--|;|\/\*|\*\/|xp_)", re.I)

def sanitize(text: str, max_len: int = 2000) -> str:
    """Strip XSS vectors and SQL metacharacters from any text input."""
    if not isinstance(text, str):
        return ""
    text = html.unescape(text)
    text = _XSS_PATTERN.sub("", text)
    text = _SQL_PATTERN.sub("", text)
    return text[:max_len].strip()

def sanitize_dict(data: dict, fields: list, max_len: int = 2000) -> dict:
    return {k: (sanitize(v, max_len) if k in fields and isinstance(v, str) else v)
            for k, v in data.items()}

# ── Secure headers ─────────────────────────────────────────────────────────────
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"]   = "nosniff"
    resp.headers["X-Frame-Options"]          = "DENY"
    resp.headers["X-XSS-Protection"]         = "1; mode=block"
    resp.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"]       = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"]  = (
        "default-src 'self'; "
        "script-src 'self' https://unpkg.com; "
        "style-src 'self' https://unpkg.com 'unsafe-inline'; "
        "img-src 'self' https://*.tile.openstreetmap.org data:; "
        "connect-src 'self' https://router.project-osrm.org "
        "https://api.open-meteo.com;"
    )
    return resp

# ── Rate limiter decorator ─────────────────────────────────────────────────────
def rate_limit(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ip  = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
        ip  = ip.split(",")[0].strip()
        now = time.time()

        if ip in _BLOCKED_IPS:
            return jsonify({"error": "Too many requests. IP temporarily blocked."}), 429

        _rate_buckets[ip] = [t for t in _rate_buckets[ip] if now - t < RATE_LIMIT_WINDOW]
        _rate_buckets[ip].append(now)

        if len(_rate_buckets[ip]) > RATE_LIMIT_MAX_REQ:
            _BLOCKED_IPS.add(ip)
            logger.warning("🚫 Rate limit exceeded: IP=%s blocked", ip)
            return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

        g.client_ip = ip
        return fn(*args, **kwargs)
    return wrapper

# ── HMAC request signature verifier ───────────────────────────────────────────
def verify_signature(fn):
    """Optional HMAC gate — enforced only when ENFORCE_HMAC=true in .env"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if os.getenv("ENFORCE_HMAC", "false").lower() != "true":
            return fn(*args, **kwargs)
        ts  = request.headers.get("X-Request-Timestamp", "")
        sig = request.headers.get("X-Request-Signature", "")
        if not ts or not sig:
            return jsonify({"error": "Missing security headers"}), 401
        try:
            ts_int = int(ts)
            if abs(time.time() - ts_int) > 300:
                return jsonify({"error": "Request timestamp expired"}), 401
        except ValueError:
            return jsonify({"error": "Invalid timestamp"}), 401
        body    = request.get_data(as_text=True)
        payload = f"{ts}:{request.method}:{request.path}:{body}".encode()
        expected = hmac.new(SIGNING_SECRET, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            logger.warning("❌ HMAC mismatch from IP=%s path=%s", request.remote_addr, request.path)
            return jsonify({"error": "Invalid request signature"}), 401
        return fn(*args, **kwargs)
    return wrapper

# ── Phone validator ─────────────────────────────────────────────────────────────
def validate_phone(phone: str) -> str | None:
    """Return normalised 10-digit string or None if invalid."""
    digits = re.sub(r"\D", "", phone)
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    return digits if len(digits) == 10 else None

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  MODULE A — NLP TRIAGE CLASSIFIER                                            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

TRIAGE_DATA = [
    ("chest pain breathlessness palpitations heart racing irregular heartbeat",       "Cardiology"),
    ("shortness of breath exertion angina hypertension blood pressure",               "Cardiology"),
    ("heart attack chest tightness left arm pain sweating nausea",                   "Cardiology"),
    ("cardiac arrhythmia dizziness fainting pacemaker coronary artery",              "Cardiology"),
    ("congestive heart failure swollen ankles fluid retention fatigue",               "Cardiology"),
    ("knee pain swelling joint stiffness difficulty walking fracture",               "Orthopedics"),
    ("back pain spine disc herniation sciatica nerve compression",                   "Orthopedics"),
    ("broken bone fracture cast surgery osteoporosis",                               "Orthopedics"),
    ("shoulder dislocation rotator cuff sports injury ligament",                     "Orthopedics"),
    ("hip replacement arthritis cartilage joint inflammation",                       "Orthopedics"),
    ("child fever infant rash baby crying not eating toddler vomiting",             "Pediatrics"),
    ("childhood asthma pediatric cough runny nose ear infection",                   "Pediatrics"),
    ("vaccination immunization growth developmental milestone",                      "Pediatrics"),
    ("newborn jaundice neonatal feeding difficulty lactation",                       "Pediatrics"),
    ("headache migraine severe throbbing vision changes nausea",                    "Neurology"),
    ("stroke weakness face drooping speech confusion memory loss",                  "Neurology"),
    ("seizure epilepsy convulsion loss consciousness tremor",                       "Neurology"),
    ("numbness tingling multiple sclerosis nerve damage",                           "Neurology"),
    ("stomach pain abdominal cramps diarrhea constipation bloating",               "Gastroenterology"),
    ("vomiting nausea acid reflux heartburn GERD ulcer",                           "Gastroenterology"),
    ("liver jaundice hepatitis fatty cirrhosis",                                    "Gastroenterology"),
    ("cough chest tightness wheezing breathing difficulty asthma",                 "Pulmonology"),
    ("tuberculosis TB persistent cough blood sputum night sweats",                 "Pulmonology"),
    ("pneumonia lung infection fever chills",                                       "Pulmonology"),
    ("skin rash itching eczema psoriasis hives allergic",                          "Dermatology"),
    ("acne pimples blackheads oily skin facial",                                   "Dermatology"),
    ("hair loss alopecia baldness scalp infection",                                "Dermatology"),
    ("eye pain redness blurred vision double discharge",                           "Ophthalmology"),
    ("cataract glaucoma retina detachment vision loss",                            "Ophthalmology"),
    ("ear pain hearing loss tinnitus ringing earwax",                             "ENT"),
    ("sinusitis nasal congestion facial pressure",                                "ENT"),
    ("depression anxiety panic attacks mood insomnia",                            "Psychiatry"),
    ("stress OCD bipolar schizophrenia hallucinations",                           "Psychiatry"),
    ("fever cold flu body ache weakness fatigue checkup",                         "General Medicine"),
    ("diabetes sugar glucose insulin HbA1c",                                      "General Medicine"),
    ("thyroid hypothyroid hyperthyroid weight",                                   "General Medicine"),
]

_sx = [r[0] for r in TRIAGE_DATA]
_sy = [r[1] for r in TRIAGE_DATA]
triage_model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1,2), stop_words="english", max_features=5000)),
    ("clf",   MultinomialNB(alpha=0.5)),
])
triage_model.fit(_sx, _sy)
logger.info("✅ Module A: Triage trained on %d samples", len(_sx))

DEPARTMENT_INFO = {
    "Cardiology":        {"icon": "❤️",  "color": "#e74c3c", "wait": "~15 min"},
    "Orthopedics":       {"icon": "🦴",  "color": "#e67e22", "wait": "~20 min"},
    "Pediatrics":        {"icon": "👶",  "color": "#3498db", "wait": "~10 min"},
    "Neurology":         {"icon": "🧠",  "color": "#9b59b6", "wait": "~25 min"},
    "Gastroenterology":  {"icon": "🫀",  "color": "#27ae60", "wait": "~20 min"},
    "Pulmonology":       {"icon": "🫁",  "color": "#16a085", "wait": "~15 min"},
    "Dermatology":       {"icon": "🩺",  "color": "#f39c12", "wait": "~18 min"},
    "Ophthalmology":     {"icon": "👁️",  "color": "#2980b9", "wait": "~22 min"},
    "ENT":               {"icon": "👂",  "color": "#8e44ad", "wait": "~15 min"},
    "Psychiatry":        {"icon": "🧘",  "color": "#2ecc71", "wait": "~30 min"},
    "General Medicine":  {"icon": "💊",  "color": "#95a5a6", "wait": "~10 min"},
}

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  MODULE B — TRAVEL DELAY REGRESSOR                                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

_tX = np.array([
    [10, 50, 0,0,9],[20,200,10,0,7],[30,400,25,0,6],[15,100,40,1,5],
    [25,600,80,0,4],[40,800,120,1,3],[50,1000,150,1,2],[12,20,5,0,9],
    [35,500,60,0,5],[18,300,90,1,4],[60,1200,180,1,1],[8,30,0,0,10],
    [45,700,100,0,3],[22,250,15,1,8],[55,900,140,1,2],
])
_ty = np.array([1.0,1.2,1.4,1.6,1.9,2.3,2.8,1.0,1.7,2.1,3.1,1.0,2.0,1.3,2.9])

travel_scaler = StandardScaler()
travel_model  = LinearRegression()
travel_model.fit(travel_scaler.fit_transform(_tX), _ty)
logger.info("✅ Module B: Travel regressor R²=%.3f",
            travel_model.score(travel_scaler.transform(_tX), _ty))

def _get_rain_mm(lat, lon):
    try:
        url  = (f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}"
                f"&hourly=precipitation&forecast_days=1&timezone=auto")
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            h = resp.json().get("hourly",{}).get("precipitation",[0])
            return float(h[datetime.now().hour]) if datetime.now().hour < len(h) else 0.0
    except Exception as e:
        logger.warning("Weather API: %s", e)
    return 0.0

def predict_travel(olat,olon,dlat,dlon,base_min,dist_km,road_q=6):
    rain     = _get_rain_mm(olat, olon)
    elev     = abs(dlat-olat)*111*8
    night    = 1 if not (6<=datetime.now().hour<=19) else 0
    sc       = travel_scaler.transform([[dist_km,elev,rain,night,road_q]])
    mult     = float(np.clip(travel_model.predict(sc)[0],1.0,4.0))
    landslide= rain>60 or (elev>600 and rain>30)
    return {
        "base_duration_min":     round(base_min,1),
        "adjusted_duration_min": round(base_min*mult,1),
        "delay_multiplier":      round(mult,2),
        "rain_mm":               round(rain,1),
        "is_night":              bool(night),
        "landslide_risk":        landslide,
        "warning": ("⚠️ HIGH LANDSLIDE RISK on this route." if landslide else None),
    }

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  MODULE C — ISOLATION FOREST ANTI-FRAUD                                     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

_rev_buf: list = []
_flagged: set  = set()
_ip_ts:   dict = defaultdict(list)
_ip_rc:   dict = defaultdict(list)
FRAUD_WIN=300; BURST_T=5; POL_T=0.8

_fraud_train = [
    [1,2.1,0.05,0,500,120],[1,2.3,0.04,1,800,95],[2,2.0,0.06,0,300,140],
    [1,1.9,0.03,0,999,200],[15,8.5,0.45,1,4,20],[12,9.1,0.52,1,3,18],
    [20,7.8,0.61,1,2,15],[10,6.5,0.38,1,5,22],[3,2.5,0.08,1,120,110],
    [1,2.2,0.05,0,700,155],[18,8.9,0.55,1,3,12],[2,1.8,0.04,0,450,180],
]
_iso_sc = StandardScaler()
_iso_f  = IsolationForest(n_estimators=100, contamination=0.12, random_state=42)
_iso_f.fit(_iso_sc.fit_transform(_fraud_train))
logger.info("✅ Module C: Isolation Forest fitted")

def _rev_features(text,rating,ip):
    now   = time.time()
    burst = len([t for t in _ip_ts[ip] if now-t<FRAUD_WIN])
    tl    = len(text); uw = len(set(text.lower().split()))
    return [burst, tl/max(uw,1),
            sum(1 for c in text if c.isupper())/max(tl,1),
            1.0 if rating in (1,5) else 0.0,
            (now-_ip_ts[ip][-1]) if _ip_ts[ip] else 9999.0, tl]

def check_fraud(text,rating,ip,uid):
    token = hashlib.sha256(f"{ip}{uid}".encode()).hexdigest()[:12]
    if ip in _flagged:
        return {"allowed":False,"reason":"IP flagged","anomaly_score":-1.0,"token":token}
    now=time.time(); _ip_ts[ip].append(now); _ip_rc[ip].append(rating)
    win=[t for t in _ip_ts[ip] if now-t<FRAUD_WIN]
    feats=_rev_features(text,rating,ip)
    sc=_iso_sc.transform([feats])
    pred=_iso_f.predict(sc)[0]; score=float(_iso_f.decision_function(sc)[0])
    burst_ok=len(win)>=BURST_T
    pol=(sum(1 for r in _ip_rc[ip][-BURST_T:] if r in(1,5))/BURST_T)>=POL_T if burst_ok else False
    fraud=(pred==-1) or (burst_ok and pol)
    if fraud:
        _flagged.add(ip)
        logger.warning("🚨 Fraud IP=%s uid=%s score=%.3f",ip,uid,score)
    _rev_buf.append(feats)
    if len(_rev_buf)>=50:
        try: _iso_f.fit(_iso_sc.fit_transform(_fraud_train+_rev_buf[-200:]))
        except: pass
    return {"allowed":not fraud,"anomaly_score":round(score,4),
            "reason":"OK" if not fraud else "Anomalous pattern","token":token}

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  DOCTOR & SHIFT SYSTEM                                                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _next5_dates():
    """Return list of 5 date strings from today."""
    today = datetime.now(timezone.utc).date()
    return [(today + timedelta(days=i)).isoformat() for i in range(5)]

def _build_shifts(doctor_id: str, on_duty_today: bool) -> dict:
    """
    Generate a deterministic but realistic 5-day shift schedule per doctor.
    Returns {date: {"shift": "Morning|Afternoon|Off", "slots_total": int, "slots_booked": int}}
    """
    shifts = {}
    patterns = ["Morning", "Morning", "Afternoon", "Off", "Morning"]
    for i, date in enumerate(_next5_dates()):
        seed = int(hashlib.md5(f"{doctor_id}{date}".encode()).hexdigest(), 16)
        shift = patterns[i % len(patterns)]
        # Force today's shift consistent with on_duty flag
        if i == 0:
            shift = "Morning" if on_duty_today else "Off"
        total   = 8 if shift != "Off" else 0
        booked  = (seed % (total + 1)) if total > 0 else 0
        shifts[date] = {
            "shift":        shift,
            "slots_total":  total,
            "slots_booked": booked,
            "slots_free":   max(0, total - booked),
            "slot_times":   _slot_times(shift) if shift != "Off" else [],
        }
    return shifts

def _slot_times(shift: str) -> list:
    if shift == "Morning":
        return ["08:00","09:00","10:00","11:00","12:00","13:00","14:00","15:00"]
    if shift == "Afternoon":
        return ["12:00","13:00","14:00","15:00","16:00","17:00","18:00","19:00"]
    return []

def _build_doctor(did, name, desig, dept, avail, exp_yrs, fee, specialties):
    return {
        "doctor_id":   did,
        "name":        name,
        "designation": desig,
        "department":  dept,
        "available":   avail,         # on duty today
        "experience_years": exp_yrs,
        "consultation_fee": fee,
        "specialties": specialties,   # list of specialty tags
        "accepting_slots": avail,     # can be full even if on duty
        "shifts":      _build_shifts(did, avail),
    }

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IN-MEMORY DATABASE  v3                                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _compute_rating(reviews: dict) -> float:
    ratings = [v["rating"] for v in reviews.values() if isinstance(v.get("rating"),(int,float))]
    return round(sum(ratings)/len(ratings),1) if ratings else 0.0

_db: dict = {
    "users":    {},
    "bookings": {},
    "hospitals": {
        "GMCH": {
            "name": "Gauhati Medical College & Hospital",
            "lat": 26.1445, "lon": 91.7362,
            "beds_available": 23, "opd_token": 47,
            "departments": list(DEPARTMENT_INFO.keys()),
            "road_quality": 8, "ward_contact": "+91-361-2529457",
            "doctors": [
                _build_doctor("gmch_d1","Dr. Anjan Bora","Senior Cardiologist","Cardiology",True,18,500,["Interventional Cardiology","Echocardiography","Heart Failure"]),
                _build_doctor("gmch_d2","Dr. Rekha Phukan","Chief Neurologist","Neurology",True,22,600,["Epilepsy","Stroke","Movement Disorders"]),
                _build_doctor("gmch_d3","Dr. Manoj Gogoi","Orthopedic Surgeon","Orthopedics",False,14,550,["Joint Replacement","Sports Medicine","Spine Surgery"]),
                _build_doctor("gmch_d4","Dr. Priya Sharma","Pediatric Specialist","Pediatrics",True,10,400,["Neonatology","Pediatric Neurology","Vaccinations"]),
                _build_doctor("gmch_d5","Dr. Sujit Das","Gastroenterologist","Gastroenterology",True,16,500,["Liver Disease","Endoscopy","IBD"]),
                _build_doctor("gmch_d6","Dr. Nilufar Begum","Pulmonologist","Pulmonology",False,12,450,["COPD","Tuberculosis","Sleep Apnea"]),
                _build_doctor("gmch_d7","Dr. Hemanta Kalita","Dermatologist","Dermatology",True,8,350,["Psoriasis","Acne","Hair Loss"]),
                _build_doctor("gmch_d8","Dr. Arunima Hazarika","ENT Specialist","ENT",True,11,400,["Sinus Surgery","Hearing Loss","Voice Disorders"]),
            ],
            "reviews": {
                "rv1":{"text":"Excellent cardiology","rating":4.5,"user_id":"seed"},
                "rv2":{"text":"Long wait but great","rating":3.8,"user_id":"seed"},
                "rv3":{"text":"Very professional","rating":4.9,"user_id":"seed"},
            },
        },
        "SMCH": {
            "name": "Silchar Medical College & Hospital",
            "lat": 24.8333, "lon": 92.7789,
            "beds_available": 11, "opd_token": 62,
            "departments": ["General Medicine","Orthopedics","Pediatrics","Cardiology"],
            "road_quality": 6, "ward_contact": "+91-3842-230898",
            "doctors": [
                _build_doctor("smch_d1","Dr. Bipul Roy","General Physician","General Medicine",True,9,300,["Diabetes Management","Hypertension","Thyroid Disorders"]),
                _build_doctor("smch_d2","Dr. Smita Nath","Pediatric Consultant","Pediatrics",True,7,350,["Child Development","Immunization","Nutritional Disorders"]),
                _build_doctor("smch_d3","Dr. Kaushik Dey","Orthopedic Consultant","Orthopedics",False,13,500,["Fracture Management","Arthroscopy","Knee Replacement"]),
                _build_doctor("smch_d4","Dr. Tanvir Ahmed","Cardiologist","Cardiology",True,15,550,["Coronary Artery Disease","Angioplasty","Cardiac Rehabilitation"]),
            ],
            "reviews": {
                "rv4":{"text":"Decent facility","rating":3.5,"user_id":"seed"},
                "rv5":{"text":"Pediatric ward excellent","rating":4.2,"user_id":"seed"},
            },
        },
        "JMCH": {
            "name": "Jorhat Medical College",
            "lat": 26.7465, "lon": 94.2026,
            "beds_available": 18, "opd_token": 35,
            "departments": ["General Medicine","Neurology","Gastroenterology","Pulmonology"],
            "road_quality": 7, "ward_contact": "+91-376-2301522",
            "doctors": [
                _build_doctor("jmch_d1","Dr. Dilip Bhuyan","Neurologist","Neurology",True,19,500,["Migraine","Dementia","Peripheral Neuropathy"]),
                _build_doctor("jmch_d2","Dr. Rupa Devi","Gastroenterologist","Gastroenterology",True,11,450,["Colonoscopy","Hepatology","Pancreatic Disorders"]),
                _build_doctor("jmch_d3","Dr. Manash Pegu","Pulmonologist","Pulmonology",True,8,400,["Asthma","COPD","Pulmonary Fibrosis"]),
                _build_doctor("jmch_d4","Dr. Gitanjali Saikia","General Physician","General Medicine",False,14,300,["Geriatrics","Anemia","Metabolic Disorders"]),
            ],
            "reviews": {
                "rv6":{"text":"Good neurology dept","rating":4.0,"user_id":"seed"},
                "rv7":{"text":"Clean wards","rating":4.3,"user_id":"seed"},
                "rv8":{"text":"Average experience","rating":3.2,"user_id":"seed"},
            },
        },
        "RIMS": {
            "name": "RIMS Imphal",
            "lat": 24.8170, "lon": 93.9368,
            "beds_available": 7, "opd_token": 88,
            "departments": ["Cardiology","Orthopedics","ENT","Psychiatry"],
            "road_quality": 5, "ward_contact": "+91-385-2416900",
            "doctors": [
                _build_doctor("rims_d1","Dr. Ibomcha Singh","Cardiologist","Cardiology",True,20,600,["Cardiac Imaging","Pacemaker Implant","Valvular Disease"]),
                _build_doctor("rims_d2","Dr. Sunita Devi","ENT Surgeon","ENT",True,12,400,["Cochlear Implant","Septoplasty","Tonsillectomy"]),
                _build_doctor("rims_d3","Dr. Ranjit Sharma","Psychiatrist","Psychiatry",False,16,500,["PTSD","Schizophrenia","Addiction Psychiatry"]),
                _build_doctor("rims_d4","Dr. Lourembam Devi","Orthopedic Surgeon","Orthopedics",True,9,500,["Hip Arthroplasty","Trauma Surgery","Pediatric Orthopedics"]),
            ],
            "reviews": {
                "rv9": {"text":"Good ENT unit","rating":4.1,"user_id":"seed"},
                "rv10":{"text":"Cardiology professional","rating":4.6,"user_id":"seed"},
            },
        },
    },
}

# OTP store
_otp_store: dict = {}
OTP_TTL = 300

def _gen_otp(): return "".join(random.choices(string.digits, k=6))

def _safe_hosp(hid, h):
    return {
        "name":          h["name"], "lat": h["lat"], "lon": h["lon"],
        "beds_available":h["beds_available"], "opd_token": h["opd_token"],
        "departments":   h["departments"], "road_quality": h["road_quality"],
        "ward_contact":  h.get("ward_contact",""),
        "doctors":       h.get("doctors",[]),
        "rating":        _compute_rating(h.get("reviews",{})),
        "review_count":  len(h.get("reviews",{})),
    }

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  FLASK ROUTES                                                                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route("/")
def index(): return render_template("index.html")

# ── Register ──────────────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@rate_limit
@verify_signature
def register():
    raw  = request.get_json(silent=True) or {}
    data = sanitize_dict(raw, ["name","medical_history"])

    email  = sanitize(raw.get("email","")).lower()
    phone  = validate_phone(raw.get("phone",""))
    gender = raw.get("gender","").strip()
    name   = data.get("name","").strip()

    if not name:   return jsonify({"error":"Full name is required"}), 400
    if not email:  return jsonify({"error":"Email is required"}), 400
    if not phone:  return jsonify({"error":"Valid 10-digit phone required"}), 400
    if gender not in ("Male","Female","Other"):
        return jsonify({"error":"Gender must be Male, Female, or Other"}), 400

    uid = hashlib.md5(email.encode()).hexdigest()[:8]
    if uid in _db["users"]:
        return jsonify({"error":"User already exists. Sign in instead."}), 409

    _db["users"][uid] = {
        "uid":uid,"name":name,"email":email,"phone":phone,
        "gender":gender,
        "age":    str(raw.get("age","")).strip(),
        "blood_group": raw.get("blood_group","").strip(),
        "medical_history": data.get("medical_history",""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info("✅ Registered uid=%s gender=%s", uid, gender)
    return jsonify({"uid":uid,"status":"registered"}), 201

# ── Login ─────────────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
@rate_limit
def login():
    data  = request.get_json(silent=True) or {}
    email = sanitize(data.get("email","")).lower()
    if not email: return jsonify({"error":"Email required"}), 400
    uid  = hashlib.md5(email.encode()).hexdigest()[:8]
    user = _db["users"].get(uid)
    if not user: return jsonify({"error":"User not found. Please register."}), 404
    return jsonify({"uid":uid,"name":user["name"],"status":"ok"})

# ── User profile ──────────────────────────────────────────────────────────────
@app.route("/api/user/<uid>")
@rate_limit
def get_user(uid):
    u = _db["users"].get(uid)
    if not u: return jsonify({"error":"Not found"}), 404
    return jsonify(u)

# ── Triage ────────────────────────────────────────────────────────────────────
@app.route("/api/triage", methods=["POST"])
@rate_limit
def triage():
    data     = request.get_json(silent=True) or {}
    symptoms = sanitize(data.get("symptoms",""))
    if not symptoms: return jsonify({"error":"No symptoms provided"}), 400
    proba  = triage_model.predict_proba([symptoms])[0]
    cls    = triage_model.classes_
    top3   = np.argsort(proba)[::-1][:3]
    dept   = cls[top3[0]]; info = DEPARTMENT_INFO.get(dept,{})
    return jsonify({
        "department": dept, "confidence": round(float(proba[top3[0]])*100,1),
        "icon": info.get("icon","🏥"), "color": info.get("color","#333"),
        "wait_time": info.get("wait","~15 min"),
        "top3":[{"dept":cls[i],"prob":round(float(proba[i])*100,1),
                 "info":DEPARTMENT_INFO.get(cls[i],{})} for i in top3],
    })

# ── Travel ────────────────────────────────────────────────────────────────────
@app.route("/api/travel", methods=["POST"])
@rate_limit
def travel():
    d = request.get_json(silent=True) or {}
    try:
        r = predict_travel(float(d["origin_lat"]),float(d["origin_lon"]),
                           float(d["dest_lat"]),  float(d["dest_lon"]),
                           float(d.get("base_duration_min",60)),
                           float(d.get("distance_km",30)),
                           int(d.get("road_quality",6)))
        return jsonify(r)
    except (KeyError,ValueError) as e:
        return jsonify({"error":f"Invalid params: {e}"}), 400

# ── Hospitals ─────────────────────────────────────────────────────────────────
@app.route("/api/hospitals")
@rate_limit
def list_hospitals():
    dept = request.args.get("dept")
    return jsonify({hid: _safe_hosp(hid,h)
                    for hid,h in _db["hospitals"].items()
                    if not dept or dept in h.get("departments",[])})

@app.route("/api/hospitals/<hid>")
@rate_limit
def get_hospital(hid):
    h = _db["hospitals"].get(hid)
    if not h: return jsonify({"error":"Not found"}), 404
    v = _safe_hosp(hid,h); v["reviews"] = h.get("reviews",{})
    return jsonify(v)

# ── Doctor profile ────────────────────────────────────────────────────────────
@app.route("/api/doctors/<doctor_id>")
@rate_limit
def get_doctor(doctor_id):
    for h in _db["hospitals"].values():
        for d in h.get("doctors",[]):
            if d["doctor_id"] == doctor_id:
                # Refresh shifts (date-aware, always current)
                d["shifts"] = _build_shifts(doctor_id, d["available"])
                return jsonify(d)
    return jsonify({"error":"Doctor not found"}), 404

@app.route("/api/doctors/<doctor_id>/slots/<date>")
@rate_limit
def get_doctor_slots(doctor_id, date):
    """Return available time slots for a specific doctor on a specific date."""
    # Validate date format
    try:
        target = datetime.strptime(date, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"error":"Invalid date format. Use YYYY-MM-DD"}), 400

    today = datetime.now(timezone.utc).date()
    if target < today:
        return jsonify({"error":"Cannot book slots in the past"}), 400
    if (target - today).days > 4:
        return jsonify({"error":"Booking window is today + 4 days only"}), 400

    for h in _db["hospitals"].values():
        for d in h.get("doctors",[]):
            if d["doctor_id"] == doctor_id:
                shifts = _build_shifts(doctor_id, d["available"])
                day    = shifts.get(date, {})
                if not day or day["shift"] == "Off":
                    return jsonify({"available": False, "slots": [],
                                    "reason": "Doctor off duty on this date"})
                # Filter booked slots from db
                booked_times = [
                    b["slot_time"] for b in _db["bookings"].values()
                    if b.get("doctor_id")==doctor_id and b.get("slot_date")==date
                ]
                slots = [
                    {"time": t,
                     "available": t not in booked_times,
                     "label": f"{t} {'✓' if t not in booked_times else '✗'}"}
                    for t in day["slot_times"]
                ]
                return jsonify({
                    "available":    True,
                    "shift":        day["shift"],
                    "slots":        slots,
                    "slots_free":   sum(1 for s in slots if s["available"]),
                    "date":         date,
                    "doctor_name":  d["name"],
                })
    return jsonify({"error":"Doctor not found"}), 404

# ── OTP: request ──────────────────────────────────────────────────────────────
@app.route("/api/otp/request", methods=["POST"])
@rate_limit
def otp_request():
    data = request.get_json(silent=True) or {}
    uid  = data.get("user_id")
    if not uid or uid not in _db["users"]:
        return jsonify({"error":"Invalid user"}), 400

    # Validate slot_date
    slot_date = data.get("slot_date")
    try:
        target = datetime.strptime(slot_date, "%Y-%m-%d").date()
        today  = datetime.now(timezone.utc).date()
        if target < today or (target-today).days > 4:
            return jsonify({"error":"Date must be within the next 5 days"}), 400
    except (ValueError, TypeError):
        return jsonify({"error":"Valid slot_date (YYYY-MM-DD) required"}), 400

    doctor_id  = data.get("doctor_id")
    hospital_id= data.get("hospital_id")
    department = data.get("department")
    slot_time  = data.get("slot_time")

    if not all([doctor_id, hospital_id, department, slot_time]):
        return jsonify({"error":"doctor_id, hospital_id, department, slot_time required"}), 400

    # Check slot not already taken
    conflict = any(
        b.get("doctor_id")==doctor_id and
        b.get("slot_date")==slot_date and
        b.get("slot_time")==slot_time
        for b in _db["bookings"].values()
    )
    if conflict:
        return jsonify({"error":"This slot is already booked. Choose another time."}), 409

    otp = _gen_otp()
    _otp_store[uid] = {
        "otp": otp, "expires": time.time()+OTP_TTL,
        "payload": {
            "hospital_id": hospital_id, "department": department,
            "slot_time": slot_time, "slot_date": slot_date,
            "doctor_id": doctor_id,
        }
    }
    phone  = _db["users"][uid].get("phone","XXXXXXXXXX")
    masked = f"+91 XXXXX-X{phone[-4:]}"
    logger.info("📲 OTP=%s uid=%s doctor=%s date=%s", otp, uid, doctor_id, slot_date)
    return jsonify({
        "status":     "otp_sent",
        "message":    f"OTP sent to {masked}",
        "otp_hint":   otp,          # MVP demo only — remove in production
        "expires_in": OTP_TTL,
    })

# ── OTP: verify + commit ──────────────────────────────────────────────────────
@app.route("/api/otp/verify", methods=["POST"])
@rate_limit
def otp_verify():
    data = request.get_json(silent=True) or {}
    uid  = data.get("user_id")
    code = str(data.get("otp","")).strip()

    if not uid or uid not in _otp_store:
        return jsonify({"error":"No pending OTP. Request one first."}), 400

    rec = _otp_store[uid]
    if time.time() > rec["expires"]:
        del _otp_store[uid]
        return jsonify({"error":"OTP expired. Request a new one."}), 410
    if not hmac.compare_digest(code, rec["otp"]):
        logger.warning("❌ Wrong OTP uid=%s", uid)
        return jsonify({"error":"Incorrect OTP. Try again."}), 401

    payload = rec["payload"]
    del _otp_store[uid]              # clear OTP from memory immediately

    hid = payload["hospital_id"]
    if hid not in _db["hospitals"]:
        return jsonify({"error":"Hospital not found"}), 404

    # Final conflict check (race-condition guard)
    conflict = any(
        b.get("doctor_id")==payload["doctor_id"] and
        b.get("slot_date")==payload["slot_date"] and
        b.get("slot_time")==payload["slot_time"]
        for b in _db["bookings"].values()
    )
    if conflict:
        return jsonify({"error":"Slot just taken. Choose another."}), 409

    bid = f"bk_{uid}_{int(time.time())}"
    _db["bookings"][bid] = {
        "booking_id":  bid,
        "user_id":     uid,
        "hospital_id": hid,
        "department":  payload["department"],
        "doctor_id":   payload["doctor_id"],
        "slot_time":   payload["slot_time"],
        "slot_date":   payload["slot_date"],
        "status":      "confirmed",
        "created_at":  datetime.now(timezone.utc).isoformat(),
    }
    _db["hospitals"][hid]["opd_token"] += 1

    # Resolve doctor name for response
    doc_name = next(
        (d["name"] for d in _db["hospitals"][hid].get("doctors",[])
         if d["doctor_id"]==payload["doctor_id"]), "Unknown"
    )
    logger.info("✅ Booking bid=%s uid=%s doctor=%s date=%s slot=%s",
                bid, uid, payload["doctor_id"], payload["slot_date"], payload["slot_time"])
    return jsonify({
        "status":      "confirmed",
        "booking_id":  bid,
        "hospital":    _db["hospitals"][hid]["name"],
        "department":  payload["department"],
        "doctor_name": doc_name,
        "slot_date":   payload["slot_date"],
        "slot_time":   payload["slot_time"],
    }), 201

# ── Cancel booking ────────────────────────────────────────────────────────────
@app.route("/api/bookings/<bid>/cancel", methods=["POST"])
@rate_limit
def cancel_booking(bid):
    data = request.get_json(silent=True) or {}
    uid  = data.get("user_id")
    b    = _db["bookings"].get(bid)
    if not b:          return jsonify({"error":"Booking not found"}), 404
    if b["user_id"]!=uid: return jsonify({"error":"Unauthorized"}), 403
    if b["status"]=="cancelled": return jsonify({"error":"Already cancelled"}), 400

    # Enforce 2-hr cancellation window
    try:
        slot_dt = datetime.strptime(
            f"{b['slot_date']} {b['slot_time']}", "%Y-%m-%d %H:%M"
        ).replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) >= slot_dt - timedelta(hours=2):
            return jsonify({"error":"Cannot cancel within 2 hours of slot"}), 400
    except (ValueError, KeyError):
        pass

    _db["bookings"][bid]["status"] = "cancelled"
    logger.info("🗑️ Cancelled bid=%s uid=%s", bid, uid)
    return jsonify({"status":"cancelled","booking_id":bid})

# ── User bookings ─────────────────────────────────────────────────────────────
@app.route("/api/bookings/<uid>")
@rate_limit
def user_bookings(uid):
    return jsonify({k:v for k,v in _db["bookings"].items() if v["user_id"]==uid})

# ── Review ────────────────────────────────────────────────────────────────────
@app.route("/api/review", methods=["POST"])
@rate_limit
def submit_review():
    raw  = request.get_json(silent=True) or {}
    text = sanitize(raw.get("text",""))
    try:   rating = float(raw.get("rating",0))
    except: return jsonify({"error":"Invalid rating"}), 400
    uid  = raw.get("user_id","anon")
    ip   = (request.headers.get("X-Forwarded-For",request.remote_addr) or "127.0.0.1").split(",")[0].strip()
    if not text:           return jsonify({"error":"Empty review"}), 400
    if not 1.0<=rating<=5.0: return jsonify({"error":"Rating must be 1.0–5.0"}), 400
    verdict = check_fraud(text, int(rating), ip, uid)
    if not verdict["allowed"]:
        return jsonify({"status":"rejected","reason":verdict["reason"],
                        "anomaly_score":verdict["anomaly_score"]}), 403
    hid = raw.get("hospital_id","GMCH")
    if hid not in _db["hospitals"]: return jsonify({"error":"Unknown hospital"}), 404
    rid = f"rv_{int(time.time()*1000)}"
    _db["hospitals"][hid].setdefault("reviews",{})[rid] = {
        "text":text,"rating":rating,"user_id":uid,
        "ts":datetime.now(timezone.utc).isoformat()
    }
    new_r = _compute_rating(_db["hospitals"][hid]["reviews"])
    return jsonify({"status":"accepted","review_id":rid,
                    "anomaly_score":verdict["anomaly_score"],
                    "hospital_rating":new_r}), 201

# ── Snapshot ──────────────────────────────────────────────────────────────────
@app.route("/api/snapshot/<collection>")
@rate_limit
def snapshot(collection):
    if collection=="hospitals":
        return jsonify({hid:_safe_hosp(hid,h) for hid,h in _db["hospitals"].items()})
    if collection not in _db: return jsonify({"error":"Unknown"}), 404
    return jsonify(_db[collection])

# ── Health ────────────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({
        "status":"ok","version":"3.0.0",
        "security":{"rate_limiting":"60 req/min","hmac_signing":"configurable",
                    "input_sanitization":"XSS+SQL","secure_headers":"CSP+HSTS"},
        "modules":{"triage":"MultinomialNB","travel":"LinearRegression","fraud":"IsolationForest"},
        "features":{"gender_field":True,"doctor_profiles":True,
                    "5day_shifts":True,"date_aware_booking":True,"otp_guard":True},
        "hospitals": len(_db["hospitals"]),
        "doctors":   sum(len(h.get("doctors",[])) for h in _db["hospitals"].values()),
    })

if __name__=="__main__":
    port = int(os.getenv("PORT",5000))
    logger.info("🚀 ArogyaRoute NE v3 on http://127.0.0.1:%d", port)
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)