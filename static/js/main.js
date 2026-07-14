/**
 * ArogyaRoute NE — Frontend v3.1 (FIXED)
 * Fixes:
 *   • crypto.subtle HMAC disabled on plain HTTP — graceful fallback, no crash
 *   • slotConfirmBar/slotConfirmText rendered inside slot HTML, not top-level
 *   • regPassword id added to HTML (unused field, but referenced safely)
 *   • COOLDOWN never blocks first call — only repeats
 *   • All onclick handlers verified present
 */
"use strict";

// ═══════════════════════════════════════════════════════
// SECURITY — INPUT SANITIZER
// (Mirrors backend sanitize() — strips XSS & SQL before any fetch)
// ═══════════════════════════════════════════════════════
const SANITIZER = {
  _xss: /<[^>]*?>|javascript:|data:|vbscript:/gi,
  _sql: /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|DECLARE|CAST|ALTER|CREATE|TRUNCATE)\b|--|;|\/\*|\*\//gi,
  clean(str, maxLen = 2000) {
    if (typeof str !== "string") return "";
    return str.replace(this._xss, "").replace(this._sql, "").trim().slice(0, maxLen);
  }
};

// ═══════════════════════════════════════════════════════
// SECURITY — HMAC REQUEST SIGNING
// Gracefully disabled on plain HTTP (crypto.subtle unavailable).
// Auto-activates on HTTPS / localhost with valid SubtleCrypto.
// ═══════════════════════════════════════════════════════
const SIGNER = {
  _key: null,
  _available: (window.isSecureContext && typeof crypto !== "undefined" && crypto.subtle),

  async init() {
    if (!this._available) return;                    // HTTP fallback — skip silently
    try {
      const raw = new TextEncoder().encode("hmac-signing-key-change-in-prod");
      this._key = await crypto.subtle.importKey(
        "raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
      );
    } catch (_) { this._available = false; }
  },

  async sign(method, path, body = "") {
    if (!this._available || !this._key) return {};   // no headers on plain HTTP
    try {
      const ts      = Math.floor(Date.now() / 1000).toString();
      const payload = new TextEncoder().encode(`${ts}:${method}:${path}:${body}`);
      const sig     = await crypto.subtle.sign("HMAC", this._key, payload);
      const hex     = Array.from(new Uint8Array(sig))
                        .map(b => b.toString(16).padStart(2, "0")).join("");
      return { "X-Request-Timestamp": ts, "X-Request-Signature": hex };
    } catch (_) { return {}; }
  }
};

// ═══════════════════════════════════════════════════════
// SECURITY — SUBMIT COOLDOWN
// Prevents rapid re-clicks on forms. First call always passes.
// ═══════════════════════════════════════════════════════
const COOLDOWN = {
  _active: {},
  block(key, ms = 2000) {
    if (this._active[key]) return false;             // already cooling down
    this._active[key] = setTimeout(() => delete this._active[key], ms);
    return true;                                     // caller may proceed
  },
  check(key) { return !this._active[key]; }          // true = safe to proceed
};

// ═══════════════════════════════════════════════════════
// APP STATE
// ═══════════════════════════════════════════════════════
const STATE = {
  uid: null, user: null,
  hospitals: {}, selectedDept: null, selectedHosp: null,
  userLatLng: null, reviewRating: 0,
  map: null, userMarker: null, hospMarkers: {}, routeLayer: null,
  snapshotTimer: null,
  bookPayload: null, otpPending: false,
  currentDoctor: null,
  selectedSlotDate: null, selectedSlotTime: null,
};

const API = p => `/api${p}`;

// ── Core fetch (all API calls go through here) ─────────
async function apiFetch(path, options = {}) {
  const method     = (options.method || "GET").toUpperCase();
  const body       = options.body   || "";
  const sigHeaders = await SIGNER.sign(method, path, body);   // {} on HTTP, signed on HTTPS

  try {
    const res  = await fetch(API(path), {
      headers: { "Content-Type": "application/json", ...sigHeaders },
      ...options,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return { data, status: res.status };
  } catch (err) {
    showToast(err.message, "error");
    throw err;
  }
}

// ═══════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════
const SPECIALTIES = [
  { name: "Cardiology",       icon: "❤️",  color: "#e74c3c" },
  { name: "Orthopedics",      icon: "🦴",  color: "#e67e22" },
  { name: "Pediatrics",       icon: "👶",  color: "#3498db" },
  { name: "Neurology",        icon: "🧠",  color: "#9b59b6" },
  { name: "Gastroenterology", icon: "🫀",  color: "#27ae60" },
  { name: "Pulmonology",      icon: "🫁",  color: "#16a085" },
  { name: "Dermatology",      icon: "🩺",  color: "#f39c12" },
  { name: "Ophthalmology",    icon: "👁️",  color: "#2980b9" },
  { name: "ENT",              icon: "👂",  color: "#8e44ad" },
  { name: "Psychiatry",       icon: "🧘",  color: "#2ecc71" },
  { name: "General Medicine", icon: "💊",  color: "#95a5a6" },
];

function el(id) { return document.getElementById(id); }

function showToast(msg, type = "info", dur = 3400) {
  const t = el("toast");
  t.textContent = msg;
  t.className   = `toast ${type}`;
  t.classList.remove("hidden");
  clearTimeout(t._t);
  t._t = setTimeout(() => t.classList.add("hidden"), dur);
}

function fmtMin(m) {
  if (m < 60) return `${Math.round(m)} min`;
  const h = Math.floor(m / 60), r = Math.round(m % 60);
  return r ? `${h}h ${r}m` : `${h}h`;
}

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

function renderStars(r, n) {
  if (!r) return `<span class="no-rating">No ratings yet</span>`;
  const full    = Math.floor(r);
  const half    = (r % 1) >= 0.5 ? "½" : "";
  const empty   = 5 - full - (half ? 1 : 0);
  const stars   = "★".repeat(full) + half + "☆".repeat(Math.max(0, empty));
  return `<span class="star-display">
    <span class="stars-filled">${stars}</span>
    <span class="rating-val">${r.toFixed(1)}</span>
    <span class="rating-count">(${n})</span>
  </span>`;
}

/** Return YYYY-MM-DD string for today + N days */
function todayPlus(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}

function fmtDate(iso) {
  // Parse as local date to avoid timezone shift
  const [y, m, d] = iso.split("-").map(Number);
  const date = new Date(y, m - 1, d);
  return date.toLocaleDateString("en-IN", { weekday: "short", day: "numeric", month: "short" });
}

function genderIcon(g) {
  return g === "Male" ? "♂" : g === "Female" ? "♀" : "⚧";
}

// ═══════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════
function showPanel(id) {
  if (id === "auth") el("authPanel").classList.add("active");
}

function switchAuthTab(tab) {
  el("loginForm").classList.toggle("hidden",    tab !== "login");
  el("registerForm").classList.toggle("hidden", tab !== "register");
  el("tabLogin").classList.toggle("active",     tab === "login");
  el("tabRegister").classList.toggle("active",  tab === "register");
  el("authMessage").classList.add("hidden");
}

function showAuthMsg(msg, isErr = false) {
  const m = el("authMessage");
  m.textContent = msg;
  m.className   = `auth-message${isErr ? " error" : ""}`;
  m.classList.remove("hidden");
}

async function doRegister() {
  if (!COOLDOWN.check("register")) return;

  // Read & sanitize all fields
  const name   = SANITIZER.clean(el("regName").value.trim());
  const email  = SANITIZER.clean(el("regEmail").value.trim()).toLowerCase();
  const phone  = (el("regPhone").value || "").replace(/\D/g, "");
  const gender = el("regGender").value;
  const age    = el("regAge").value;
  const blood  = el("regBlood").value;
  const hist   = SANITIZER.clean((el("regHistory").value || "").trim(), 500);

  // Frontend validation
  if (!name)           return showAuthMsg("Full name is required.", true);
  if (!email)          return showAuthMsg("Email address is required.", true);
  if (phone.length !== 10) return showAuthMsg("Enter a valid 10-digit phone number.", true);
  if (!gender)         return showAuthMsg("Please select your gender.", true);

  COOLDOWN.block("register", 3000);
  try {
    const { data } = await apiFetch("/auth/register", {
      method: "POST",
      body:   JSON.stringify({ name, email, phone, gender, age, blood_group: blood, medical_history: hist }),
    });
    showAuthMsg(`✓ Account created! (UID: ${data.uid}) — Now sign in.`);
    setTimeout(() => switchAuthTab("login"), 1800);
  } catch (_) { /* toast shown by apiFetch */ }
}

async function doLogin() {
  if (!COOLDOWN.check("login")) return;
  const email = SANITIZER.clean(el("loginEmail").value.trim()).toLowerCase();
  if (!email) return showAuthMsg("Enter your email address.", true);
  COOLDOWN.block("login", 2000);
  try {
    const { data } = await apiFetch("/auth/login", {
      method: "POST",
      body:   JSON.stringify({ email }),
    });
    STATE.uid  = data.uid;
    STATE.user = data;
    await onLoginSuccess();
  } catch (_) {}
}

async function onLoginSuccess() {
  try {
    const { data } = await apiFetch(`/user/${STATE.uid}`);
    STATE.user = data;
  } catch (_) {}

  el("authPanel").classList.remove("active");
  el("mainDashboard").classList.remove("hidden");
  el("navLoginBtn").classList.add("hidden");
  el("navLogoutBtn").classList.remove("hidden");
  el("connectionBadge").textContent = "● Connected";
  el("connectionBadge").classList.add("connected");

  renderProfile();
  buildSpecialtyGrid();
  initMap();
  loadHospitals();
  startSnapshotPolling();
  showToast(`Welcome, ${STATE.user.name || "Patient"} 🏥`, "ok");
}

function logout() {
  STATE.uid = null; STATE.user = null;
  el("mainDashboard").classList.add("hidden");
  el("navLoginBtn").classList.remove("hidden");
  el("navLogoutBtn").classList.add("hidden");
  el("authPanel").classList.add("active");
  el("connectionBadge").textContent = "● Connecting...";
  el("connectionBadge").classList.remove("connected");
  clearInterval(STATE.snapshotTimer);
  showToast("Signed out.", "info");
}

function refreshProfile() {
  if (!STATE.uid) return;
  apiFetch(`/user/${STATE.uid}`)
    .then(({ data }) => { STATE.user = data; renderProfile(); })
    .catch(() => {});
}

function renderProfile() {
  const u = STATE.user || {};
  el("profileName").textContent    = u.name         || "—";
  el("profileAge").textContent     = u.age           ? `Age: ${u.age}` : "Age: —";
  el("profileBlood").textContent   = u.blood_group  || "—";
  el("profileGender").textContent  = u.gender        ? `${genderIcon(u.gender)} ${u.gender}` : "—";
  el("profilePhone").textContent   = u.phone         ? `📱 +91 ${u.phone}` : "📱 —";
  el("profileHistory").textContent = u.medical_history || "No medical history recorded.";
  el("profileAvatar").textContent  = (u.name || "?")[0].toUpperCase();
}

// ═══════════════════════════════════════════════════════
// MODULE A — TRIAGE
// ═══════════════════════════════════════════════════════
async function runTriage() {
  const symptoms = SANITIZER.clean(el("symptomsInput").value.trim());
  if (!symptoms) return showToast("Please describe your symptoms first.", "error");

  el("triageResult").classList.add("hidden");
  el("triageSpinner").classList.remove("hidden");

  try {
    const { data } = await apiFetch("/triage", {
      method: "POST",
      body:   JSON.stringify({ symptoms }),
    });
    el("triageSpinner").classList.add("hidden");
    renderTriageResult(data);
    highlightSpecTile(data.department);
  } catch (_) {
    el("triageSpinner").classList.add("hidden");
  }
}

function renderTriageResult(res) {
  const p = el("triagePrimary");
  p.innerHTML = `
    <span class="triage-dept-icon">${res.icon}</span>
    <div>
      <div class="triage-dept-name" style="color:${res.color}">${res.department}</div>
      <div class="triage-conf">Confidence: <strong>${res.confidence}%</strong></div>
      <div class="triage-wait">Est. wait: ${res.wait_time}</div>
    </div>`;
  p.style.borderLeftColor = res.color;

  el("triageAlternatives").innerHTML = (res.top3 || []).slice(1).map(d =>
    `<span class="triage-alt-pill">${d.info.icon || "🏥"} ${d.dept} (${d.prob}%)</span>`
  ).join("");

  STATE.selectedDept = res.department;
  el("triageResult").classList.remove("hidden");
}

function findHospitalsForDept() {
  if (!STATE.selectedDept) return;
  loadHospitals(STATE.selectedDept);
  document.querySelector(".grid-map")?.scrollIntoView({ behavior: "smooth" });
}

// ═══════════════════════════════════════════════════════
// SPECIALTY GRID
// ═══════════════════════════════════════════════════════
function buildSpecialtyGrid() {
  el("specialtyGrid").innerHTML = SPECIALTIES.map(s => `
    <div class="spec-tile" id="spec_${s.name.replace(/\s/g, "_")}"
         onclick="selectSpecialty('${s.name}')">
      <span class="spec-icon">${s.icon}</span>
      <span class="spec-name">${s.name}</span>
    </div>`).join("");
}

function selectSpecialty(name) {
  STATE.selectedDept = name;
  highlightSpecTile(name);
  loadHospitals(name);
  document.querySelector(".grid-map")?.scrollIntoView({ behavior: "smooth" });
}

function highlightSpecTile(name) {
  document.querySelectorAll(".spec-tile").forEach(t => t.classList.remove("active"));
  const tile = el("spec_" + name.replace(/\s/g, "_"));
  if (tile) tile.classList.add("active");
}

// ═══════════════════════════════════════════════════════
// MAP — DEBOUNCED OSRM ROUTING
// ═══════════════════════════════════════════════════════
function _clearRoute() {
  if (STATE.routeLayer) { STATE.routeLayer.remove(); STATE.routeLayer = null; }
}

const _debouncedRoute = debounce((hid) => { _clearRoute(); _computeRoute(hid); }, 420);

function initMap() {
  if (STATE.map) return;

  STATE.map = L.map("mapContainer", { preferCanvas: true }).setView([26.2, 92.8], 7);

  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "© OpenStreetMap contributors", maxZoom: 18,
  }).addTo(STATE.map);

  STATE.map.on("click", e => setUserLoc(e.latlng.lat, e.latlng.lng));

  placeHospMarkers();

  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(
      p  => setUserLoc(p.coords.latitude, p.coords.longitude),
      () => setUserLoc(26.35, 92.68)
    );
  } else {
    setUserLoc(26.35, 92.68);
  }
}

function setUserLoc(lat, lng) {
  STATE.userLatLng = { lat, lng };
  if (STATE.userMarker) STATE.userMarker.remove();

  STATE.userMarker = L.marker([lat, lng], {
    icon: L.divIcon({
      className: "",
      iconAnchor: [7, 7],
      html: `<div style="width:14px;height:14px;border-radius:50%;
             background:#e74c3c;border:3px solid #fff;
             box-shadow:0 0 0 3px rgba(231,76,60,.35)"></div>`,
    }),
  }).addTo(STATE.map).bindPopup("📍 Your Location").openPopup();

  el("mapLegend").innerHTML = "📍 Location set. Click a hospital card to get route.";
  if (STATE.selectedHosp) _debouncedRoute(STATE.selectedHosp);
}

function placeHospMarkers() {
  Object.values(STATE.hospMarkers).forEach(m => m.remove());
  STATE.hospMarkers = {};

  Object.entries(STATE.hospitals).forEach(([hid, h]) => {
    if (!h.lat || !h.lon) return;
    const marker = L.marker([h.lat, h.lon], {
      icon: L.divIcon({
        className: "",
        iconAnchor: [0, 12],
        html: `<div style="background:#0d4f5c;color:#fff;padding:3px 8px;
               border-radius:4px;font-size:11px;font-weight:700;
               white-space:nowrap;box-shadow:0 2px 6px rgba(0,0,0,.3)">
               🏥 ${hid}</div>`,
      }),
    }).addTo(STATE.map);
    marker.on("click", () => selectHospital(hid));
    STATE.hospMarkers[hid] = marker;
  });
}

async function _computeRoute(hid) {
  const h = STATE.hospitals[hid];
  if (!h || !STATE.userLatLng) return;
  const { lat: oLat, lng: oLng } = STATE.userLatLng;

  const osrmUrl =
    `https://router.project-osrm.org/route/v1/driving/` +
    `${oLng},${oLat};${h.lon},${h.lat}?overview=full&geometries=geojson`;

  try {
    const res    = await fetch(osrmUrl, { signal: AbortSignal.timeout(8000) });
    const json   = await res.json();

    if (json.routes && json.routes[0]) {
      const route   = json.routes[0];
      const distKm  = (route.distance / 1000).toFixed(1);
      const baseMin = (route.duration / 60).toFixed(1);

      // Smooth fade-in polyline
      STATE.routeLayer = L.geoJSON(route.geometry, {
        style: { color: "#0d4f5c", weight: 4, opacity: 0, dashArray: "8 4" },
      }).addTo(STATE.map);

      let op = 0;
      const fade = setInterval(() => {
        op += 0.15;
        if (op >= 0.85) { op = 0.85; clearInterval(fade); }
        STATE.routeLayer.setStyle({ opacity: op });
      }, 30);

      STATE.map.fitBounds(STATE.routeLayer.getBounds(), { padding: [30, 30] });

      el("tDist").textContent = `${distKm} km`;
      el("tBase").textContent = fmtMin(parseFloat(baseMin));
      el("travelInfo").classList.remove("hidden");

      await getTravelDelay(oLat, oLng, h.lat, h.lon,
        parseFloat(baseMin), parseFloat(distKm), h.road_quality || 6);
    }
  } catch (_) {
    // Fallback: haversine estimate
    const d  = haversine(oLat, oLng, h.lat, h.lon).toFixed(1);
    const bm = (d / 0.6).toFixed(1);
    el("tDist").textContent = `~${d} km (est.)`;
    el("tBase").textContent = fmtMin(parseFloat(bm));
    el("travelInfo").classList.remove("hidden");
    await getTravelDelay(oLat, oLng, h.lat, h.lon,
      parseFloat(bm), parseFloat(d), h.road_quality || 6);
    showToast("OSRM offline — distance estimated.", "info");
  }
}

async function getTravelDelay(oLat, oLon, dLat, dLon, baseMin, distKm, roadQ) {
  try {
    const { data } = await apiFetch("/travel", {
      method: "POST",
      body:   JSON.stringify({
        origin_lat: oLat, origin_lon: oLon,
        dest_lat:   dLat, dest_lon:   dLon,
        base_duration_min: baseMin,
        distance_km:       distKm,
        road_quality:      roadQ,
      }),
    });
    el("tAdj").textContent  = fmtMin(data.adjusted_duration_min);
    el("tRain").textContent = `${data.rain_mm} mm`;
    el("tDelay").textContent= `×${data.delay_multiplier}`;
    const lw = el("landslideWarning");
    if (data.landslide_risk) {
      lw.classList.remove("hidden");
      showToast("⚠️ Landslide risk on this route!", "error", 5000);
    } else {
      lw.classList.add("hidden");
    }
  } catch (_) {}
}

function haversine(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLa = (lat2 - lat1) * Math.PI / 180;
  const dLo = (lon2 - lon1) * Math.PI / 180;
  const a   = Math.sin(dLa/2)**2 +
    Math.cos(lat1*Math.PI/180) * Math.cos(lat2*Math.PI/180) * Math.sin(dLo/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// ═══════════════════════════════════════════════════════
// HOSPITALS
// ═══════════════════════════════════════════════════════
async function loadHospitals(dept = null) {
  try {
    const path = dept ? `/hospitals?dept=${encodeURIComponent(dept)}` : "/hospitals";
    const { data } = await apiFetch(path);
    STATE.hospitals = data;
    renderHospList(data);
    renderResDash(data);
    if (STATE.map) placeHospMarkers();
  } catch (_) {}
}

function selectHospital(hid) {
  STATE.selectedHosp = hid;
  document.querySelectorAll(".hospital-item")
    .forEach(i => i.classList.toggle("selected", i.dataset.hid === hid));
  el("bookHospital").value   = hid;
  el("reviewHospital").value = hid;
  _debouncedRoute(hid);
}

function renderHospList(data) {
  const list = el("hospitalList");
  const entries = Object.entries(data);
  if (!entries.length) {
    list.innerHTML = `<div class="empty-state">No hospitals match this specialty.</div>`;
    return;
  }
  list.innerHTML = entries.map(([hid, h]) => {
    const beds  = h.beds_available ?? 0;
    const bc    = beds > 15 ? "beds-ok" : beds > 5 ? "beds-low" : "beds-crit";
    const avail = (h.doctors || []).filter(d => d.available).length;
    const total = (h.doctors || []).length;
    return `
      <div class="hospital-item" data-hid="${hid}" onclick="selectHospital('${hid}')">
        <div class="h-name">🏥 ${h.name}</div>
        <div class="h-meta">
          <span class="h-badge ${bc}">🛏 ${beds} beds</span>
          <span class="h-badge opd">🎟 Token #${h.opd_token}</span>
          <span class="h-badge doctor">👨‍⚕️ ${avail}/${total} on duty</span>
          <span class="h-badge phone">📞 ${h.ward_contact || "—"}</span>
        </div>
        <div class="h-rating">${renderStars(h.rating, h.review_count)}</div>
        <div class="h-actions">
          <button class="btn-primary btn-sm"
            onclick="event.stopPropagation(); openBookingModal('${hid}')">
            Book Slot
          </button>
          <button class="btn-outline btn-sm"
            onclick="event.stopPropagation(); showDoctorList('${hid}')">
            View Doctors
          </button>
        </div>
      </div>`;
  }).join("");
}

// ═══════════════════════════════════════════════════════
// RESOURCE DASHBOARD
// ═══════════════════════════════════════════════════════
function renderResDash(data) {
  const grid = el("resourceGrid");
  const entries = Object.entries(data);
  if (!entries.length) { grid.innerHTML = `<div class="empty-state">No data.</div>`; return; }

  grid.innerHTML = entries.map(([hid, h]) => {
    const beds = h.beds_available ?? 0;
    const bc   = beds > 15 ? "ok" : beds > 5 ? "warn" : "danger";
    const tc   = h.opd_token > 60 ? "warn" : "neutral";
    const rows = (h.doctors || []).map(d => `
      <tr class="doctor-row" onclick="openDoctorProfile('${d.doctor_id}')" style="cursor:pointer">
        <td class="doc-name">${d.name}</td>
        <td class="doc-desig">${d.designation}</td>
        <td><span class="avail-badge ${d.available ? "avail-yes" : "avail-no'}">
          ${d.available ? "● On Duty" : "○ Off Duty"}
        </span></td>
      </tr>`).join("");

    return `
      <div class="resource-hospital-card">
        <div class="rh-header">
          <span>🏥 ${h.name}</span>
          <span class="rh-contact">📞 ${h.ward_contact || "—"}</span>
        </div>
        <div class="rh-stats">
          <div class="rh-stat">
            <div class="rh-stat-label">Beds</div>
            <div class="rh-stat-val ${bc}">${beds}</div>
          </div>
          <div class="rh-stat">
            <div class="rh-stat-label">OPD Token</div>
            <div class="rh-stat-val ${tc}">#${h.opd_token}</div>
          </div>
          <div class="rh-stat">
            <div class="rh-stat-label">Rating</div>
            <div class="rh-stat-val neutral">${h.rating ? `★ ${h.rating.toFixed(1)}` : "—"}</div>
          </div>
          <div class="rh-stat">
            <div class="rh-stat-label">Road</div>
            <div class="rh-stat-val neutral">${h.road_quality}/10</div>
          </div>
        </div>
        <div class="doctor-directory">
          <div class="doctor-dir-title">🩺 On-Duty Clinical Directory
            <span class="hint" style="font-size:.7rem;color:#999"> (click row for profile)</span>
          </div>
          <table class="doctor-table">
            <thead><tr><th>Doctor</th><th>Designation</th><th>Status</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div class="rh-footer">
          <button class="btn-primary btn-sm" onclick="openBookingModal('${hid}')">
            Book Slot →
          </button>
        </div>
      </div>`;
  }).join("");
}

function startSnapshotPolling() {
  clearInterval(STATE.snapshotTimer);
  STATE.snapshotTimer = setInterval(async () => {
    try {
      const { data } = await apiFetch("/snapshot/hospitals");
      Object.entries(data).forEach(([hid, h]) => {
        if (STATE.hospitals[hid]) Object.assign(STATE.hospitals[hid], {
          beds_available: h.beds_available,
          opd_token:      h.opd_token,
          rating:         h.rating,
          review_count:   h.review_count,
          doctors:        h.doctors,
        });
      });
      renderHospList(STATE.hospitals);
      renderResDash(STATE.hospitals);
    } catch (_) {}
  }, 12000);
}

// ═══════════════════════════════════════════════════════
// DOCTOR PROFILE MODAL
// ═══════════════════════════════════════════════════════
async function openDoctorProfile(docId) {
  el("doctorProfileModal").classList.remove("hidden");
  el("doctorProfileBody").innerHTML =
    `<div class="empty-state"><span class="spinner"></span> Loading profile…</div>`;
  try {
    const { data } = await apiFetch(`/doctors/${docId}`);
    STATE.currentDoctor = data;
    renderDoctorProfile(data);
  } catch (_) {
    el("doctorProfileBody").innerHTML =
      `<div class="empty-state" style="color:#c0392b">Failed to load profile.</div>`;
  }
}

function renderDoctorProfile(d) {
  const bg      = d.available ? "#0d4f5c" : "#95a5a6";
  const initials = d.name.split(" ").map(w => w[0]).join("").slice(0, 2);
  const specs   = (d.specialties || []).map(s => `<span class="spec-chip">${s}</span>`).join("");

  const dates = Object.keys(d.shifts || {});
  const shiftCells = dates.map((date, i) => {
    const s     = d.shifts[date];
    const label = i === 0 ? "Today" : i === 1 ? "Tomorrow" : fmtDate(date);
    const cls   = s.shift === "Off" ? "shift-off"
                : s.slots_free === 0 ? "shift-full"
                : s.slots_free <= 2  ? "shift-few" : "shift-ok";
    const clickable = s.shift !== "Off"
      ? `onclick="handleShiftClick('${date}','${d.doctor_id}')"` : "";
    return `
      <div class="shift-cell ${cls}" ${clickable}>
        <div class="shift-day">${label}</div>
        <div class="shift-time">${s.shift === "Off" ? "Off Duty" : s.shift}</div>
        <div class="shift-slots">${s.shift === "Off" ? "—" : `${s.slots_free}/${s.slots_total} free`}</div>
      </div>`;
  }).join("");

  el("doctorProfileBody").innerHTML = `
    <div class="doc-profile-header">
      <div class="doc-avatar-lg" style="background:${bg}">${initials}</div>
      <div class="doc-profile-info">
        <h2 class="doc-profile-name">${d.name}</h2>
        <div class="doc-profile-desig">${d.designation}</div>
        <div class="doc-profile-dept">${d.department}</div>
        <div class="doc-status-row">
          <span class="avail-badge ${d.available ? "avail-yes" : "avail-no"}">
            ${d.available ? "● On Duty Today" : "○ Off Duty Today"}
          </span>
          <span class="avail-badge ${d.accepting_slots ? "avail-yes" : "avail-no"}">
            ${d.accepting_slots ? "✓ Accepting Slots" : "✗ Slots Full"}
          </span>
        </div>
      </div>
    </div>
    <div class="doc-profile-grid">
      <div class="doc-info-card">
        <span class="doc-info-label">Experience</span>
        <span class="doc-info-val">${d.experience_years} yrs</span>
      </div>
      <div class="doc-info-card fee-card">
        <span class="doc-info-label">Consultation Fee</span>
        <span class="doc-info-val">₹${d.consultation_fee}</span>
      </div>
    </div>
    <div class="doc-specialties">
      <div class="doc-section-title">Specializations</div>
      <div class="spec-chips">${specs}</div>
    </div>
    <div class="doc-shifts">
      <div class="doc-section-title">5-Day Shift Schedule</div>
      <div class="shift-legend">
        <span style="color:#27ae60">●</span> Available &nbsp;
        <span style="color:#e67e22">●</span> Few Left &nbsp;
        <span style="color:#c0392b">●</span> Full &nbsp;
        <span style="color:#aaa">●</span> Off Duty
        <span style="font-size:.7rem;margin-left:8px">(click to select date)</span>
      </div>
      <div class="shift-grid">${shiftCells}</div>
    </div>
    <button class="btn-primary full-width mt-sm"
            onclick="bookThisDoctor('${d.doctor_id}')">
      Book This Doctor →
    </button>`;
}

function showDoctorList(hid) {
  const h = STATE.hospitals[hid];
  if (!h) return;
  el("doctorListModal").classList.remove("hidden");
  el("doctorListTitle").textContent = `Doctors at ${h.name}`;
  el("doctorListBody").innerHTML = (h.doctors || []).map(d => `
    <div class="doctor-list-item" onclick="openDoctorProfile('${d.doctor_id}')">
      <div class="doc-li-avatar" style="background:${d.available ? "#0d4f5c" : "#95a5a6"}">
        ${d.name.split(" ").map(w => w[0]).join("").slice(0, 2)}
      </div>
      <div class="doc-li-info">
        <div class="doc-li-name">${d.name}</div>
        <div class="doc-li-desig">${d.designation} · ${d.department}</div>
        <div class="doc-li-meta">
          <span>${d.experience_years} yrs</span>
          <span>₹${d.consultation_fee}</span>
          <span class="avail-badge ${d.available ? "avail-yes" : "avail-no"}"
                style="font-size:.68rem;padding:1px 7px">
            ${d.available ? "On Duty" : "Off Duty"}
          </span>
        </div>
      </div>
    </div>`).join("");
}

// ═══════════════════════════════════════════════════════
// SHIFT CLICK → SLOT PICKER
// ═══════════════════════════════════════════════════════
async function handleShiftClick(date, docId) {
  STATE.selectedSlotDate = date;
  closeModal("doctorProfileModal");
  await openSlotPicker(docId, date);
}

async function bookThisDoctor(docId) {
  await openSlotPicker(docId, todayPlus(0));
}

async function openSlotPicker(docId, date) {
  el("slotPickerModal").classList.remove("hidden");
  el("slotPickerBody").innerHTML =
    `<div class="empty-state"><span class="spinner"></span> Loading slots…</div>`;
  renderDateTabs(docId, date);
  await loadSlots(docId, date);
}

function renderDateTabs(docId, activeDate) {
  el("slotDateTabs").innerHTML = Array.from({ length: 5 }, (_, i) => {
    const d     = todayPlus(i);
    const label = i === 0 ? "Today" : i === 1 ? "Tomorrow" : fmtDate(d);
    return `<button class="date-tab ${d === activeDate ? "active" : ""}"
              onclick="switchSlotDate('${docId}','${d}')">${label}</button>`;
  }).join("");
}

async function switchSlotDate(docId, date) {
  STATE.selectedSlotDate = date;
  STATE.selectedSlotTime = null;
  renderDateTabs(docId, date);
  await loadSlots(docId, date);
}

async function loadSlots(docId, date) {
  try {
    const { data } = await apiFetch(`/doctors/${docId}/slots/${date}`);
    renderSlots(data, docId, date);
  } catch (_) {
    el("slotPickerBody").innerHTML =
      `<div class="empty-state" style="color:#c0392b">Could not load slots.</div>`;
  }
}

function renderSlots(data, docId, date) {
  if (!data.available) {
    el("slotPickerBody").innerHTML =
      `<div class="empty-state">🏖 ${data.reason || "No slots available on this date."}</div>`;
    return;
  }

  // slotConfirmBar is rendered INSIDE the slot picker body (not a top-level DOM id)
  el("slotPickerBody").innerHTML = `
    <div class="slot-shift-info">
      Shift: <strong>${data.shift}</strong> ·
      ${data.slots_free} free slots · Dr. ${data.doctor_name}
    </div>
    <div class="slot-grid" id="slotGrid">
      ${(data.slots || []).map(s => `
        <button class="slot-btn ${s.available ? "slot-free" : "slot-taken"}"
          ${s.available
            ? `onclick="selectSlot('${s.time}','${docId}','${date}',this)"`
            : "disabled"}>
          ${s.time}<br>
          <span class="slot-status">${s.available ? "Available" : "Booked"}</span>
        </button>`).join("")}
    </div>
    <div id="slotConfirmBar" class="slot-confirm-bar hidden">
      <span id="slotConfirmText"></span>
      <button class="btn-primary btn-sm" onclick="proceedToOTP()">
        Confirm &amp; Get OTP →
      </button>
    </div>`;
}

function selectSlot(time, docId, date, btn) {
  STATE.selectedSlotTime = time;
  STATE.selectedSlotDate = date;
  // Ensure currentDoctor has doctor_id
  if (!STATE.currentDoctor) STATE.currentDoctor = {};
  STATE.currentDoctor.doctor_id = docId;

  document.querySelectorAll(".slot-btn").forEach(b => b.classList.remove("selected"));
  btn.classList.add("selected");

  const bar  = el("slotConfirmBar");
  const text = el("slotConfirmText");
  if (bar && text) {
    bar.classList.remove("hidden");
    text.textContent = `Selected: ${time} on ${fmtDate(date)}`;
  }
}

async function proceedToOTP() {
  if (!STATE.selectedSlotTime || !STATE.selectedSlotDate) {
    showToast("Please select a time slot first.", "error"); return;
  }
  if (!STATE.uid) { showToast("Please sign in first.", "error"); return; }

  // Find hospital and department for this doctor
  let hid  = Object.keys(STATE.hospitals)[0] || "GMCH";
  let dept = "General Medicine";
  for (const [h, hdata] of Object.entries(STATE.hospitals)) {
    const doc = (hdata.doctors || []).find(d => d.doctor_id === STATE.currentDoctor?.doctor_id);
    if (doc) { hid = h; dept = doc.department; break; }
  }

  STATE.bookPayload = {
    hospital_id: hid,
    department:  dept,
    doctor_id:   STATE.currentDoctor?.doctor_id,
    slot_date:   STATE.selectedSlotDate,
    slot_time:   STATE.selectedSlotTime,
  };

  closeModal("slotPickerModal");
  await _sendOTPRequest();
  el("bookingModal").classList.remove("hidden");
}

// ═══════════════════════════════════════════════════════
// BOOKING MODAL — hospital-level fallback + OTP steps
// ═══════════════════════════════════════════════════════
function openBookingModal(hid) {
  if (!STATE.uid) { showToast("Please sign in first.", "error"); return; }
  el("bookHospital").value = hid;
  el("bookingResult").classList.add("hidden");
  el("otpStep").classList.add("hidden");
  el("bookStep").classList.remove("hidden");
  el("bookingModal").classList.remove("hidden");
  STATE.otpPending = false;
}

async function requestOTP() {
  if (!COOLDOWN.check("otp")) return;
  const hid  = el("bookHospital").value;
  const dept = el("bookDept").value;
  const slot = el("bookSlot").value;
  const date = el("bookDate").value;

  if (!hid || !dept || !slot || !date) {
    showToast("Please fill all booking fields.", "error"); return;
  }

  STATE.bookPayload = {
    hospital_id: hid, department: dept,
    slot_time:   slot, slot_date: date, doctor_id: null,
  };
  COOLDOWN.block("otp", 5000);
  await _sendOTPRequest();
}

async function _sendOTPRequest() {
  if (!STATE.bookPayload || !STATE.uid) return;
  try {
    const { data } = await apiFetch("/otp/request", {
      method: "POST",
      body:   JSON.stringify({ user_id: STATE.uid, ...STATE.bookPayload }),
    });
    el("bookStep").classList.add("hidden");
    el("otpStep").classList.remove("hidden");
    el("otpMessage").textContent = data.message;
    el("otpHint").textContent    = `Demo OTP: ${data.otp_hint}`;
    el("otpInput").value         = "";
    el("bookingResult").classList.add("hidden");
    showToast("OTP sent to your registered phone.", "ok");
  } catch (_) {}
}

async function verifyOTPAndBook() {
  if (!COOLDOWN.check("verify")) return;
  const otp = el("otpInput").value.trim();
  if (!otp || otp.length !== 6) {
    showToast("Enter the 6-digit OTP.", "error"); return;
  }
  COOLDOWN.block("verify", 3000);
  try {
    const { data } = await apiFetch("/otp/verify", {
      method: "POST",
      body:   JSON.stringify({ user_id: STATE.uid, otp }),
    });
    el("otpInput").value = "";  // wipe OTP from DOM immediately

    const r = el("bookingResult");
    r.innerHTML = `
      ✓ Booking confirmed!<br>
      ${data.doctor_name ? `<strong>Dr. ${data.doctor_name}</strong> · ` : ""}
      ${data.department} @ ${data.hospital}<br>
      📅 <strong>${data.slot_date}</strong> &nbsp;
      🕐 <strong>${data.slot_time}</strong><br>
      ID: <code>${data.booking_id}</code>`;
    r.className = "review-result";
    r.classList.remove("hidden");
    el("otpStep").classList.add("hidden");
    showToast("Booking confirmed! 🎉", "ok");
    STATE.bookPayload = null;
    STATE.selectedSlotDate = null;
    STATE.selectedSlotTime = null;
    setTimeout(() => closeModal("bookingModal"), 4000);
  } catch (_) {
    el("otpInput").value = "";  // wipe even on failure
  }
}

async function showBookingsModal() {
  if (!STATE.uid) return;
  el("myBookingsList").innerHTML = "<div class='empty-state'>Loading…</div>";
  el("myBookingsModal").classList.remove("hidden");
  try {
    const { data } = await apiFetch(`/bookings/${STATE.uid}`);
    const entries  = Object.values(data);
    if (!entries.length) {
      el("myBookingsList").innerHTML = "<div class='empty-state'>No bookings yet.</div>";
      return;
    }
    el("myBookingsList").innerHTML = entries.map(b => `
      <div class="booking-item">
        <div class="b-id">ID: ${b.booking_id}</div>
        <div class="b-dept">🏥 ${b.hospital_id} · ${b.department}</div>
        <div class="b-meta">
          📅 ${b.slot_date || "—"} &nbsp;
          🕐 ${b.slot_time} &nbsp;·&nbsp; ${b.created_at.slice(0, 10)}
        </div>
        <div class="b-bottom">
          <span class="b-confirmed ${b.status === "cancelled" ? "b-cancelled" : ""}">
            ${b.status === "confirmed" ? "✓ Confirmed" : "✗ Cancelled"}
          </span>
          ${b.status === "confirmed"
            ? `<button class="btn-outline btn-sm"
                       onclick="cancelBooking('${b.booking_id}')">Cancel</button>`
            : ""}
        </div>
      </div>`).join("");
  } catch (_) {}
}

async function cancelBooking(bid) {
  if (!confirm("Are you sure you want to cancel this booking?")) return;
  try {
    await apiFetch(`/bookings/${bid}/cancel`, {
      method: "POST",
      body:   JSON.stringify({ user_id: STATE.uid }),
    });
    showToast("Booking cancelled.", "info");
    showBookingsModal();
  } catch (_) {}
}

function closeModal(id) {
  el(id).classList.add("hidden");
}

// ═══════════════════════════════════════════════════════
// HALF-STAR REVIEW SYSTEM
// ═══════════════════════════════════════════════════════
function buildHalfStarPicker() {
  const row = el("starRow");
  if (!row) return;
  row.innerHTML = "";

  for (let i = 1; i <= 5; i++) {
    const span = document.createElement("span");
    span.className = "star-outer";
    span.innerHTML = `
      <span class="star-half left"  data-val="${Math.max(0.5, i - 0.5)}">◐</span>
      <span class="star-half right" data-val="${i}">★</span>`;
    row.appendChild(span);
  }

  row.querySelectorAll(".star-half").forEach(half => {
    half.addEventListener("click", () => {
      const val = parseFloat(half.dataset.val);
      STATE.reviewRating       = val;
      el("reviewRating").value = val;
      updateStarDisplay(val);
    });
  });
}

function updateStarDisplay(r) {
  el("starRow").querySelectorAll(".star-half")
    .forEach(h => h.classList.toggle("active", parseFloat(h.dataset.val) <= r));
  const l = el("ratingLabel");
  if (l) l.textContent = r > 0 ? `${r.toFixed(1)} ★` : "";
}

async function submitReview() {
  if (!COOLDOWN.check("review")) return;
  const text   = SANITIZER.clean(el("reviewText").value.trim());
  const rating = STATE.reviewRating;
  const hid    = el("reviewHospital").value;

  if (!STATE.uid) return showToast("Please sign in first.", "error");
  if (!text)      return showToast("Please write your review.", "error");
  if (!rating)    return showToast("Please select a star rating.", "error");

  COOLDOWN.block("review", 4000);
  try {
    const { data } = await apiFetch("/review", {
      method: "POST",
      body:   JSON.stringify({ text, rating, hospital_id: hid, user_id: STATE.uid }),
    });
    const r = el("reviewResult");
    r.innerHTML = `✓ Review accepted! New hospital rating: <strong>★ ${data.hospital_rating}</strong>`;
    r.className = "review-result";
    r.classList.remove("hidden");
    el("reviewText").value  = "";
    STATE.reviewRating      = 0;
    el("reviewRating").value = 0;
    updateStarDisplay(0);
    showToast("Review submitted. Thank you!", "ok");
    loadHospitals(STATE.selectedDept || null);
  } catch (err) {
    const r = el("reviewResult");
    r.textContent = `🚨 ${err.message}`;
    r.className   = "review-result error";
    r.classList.remove("hidden");
  }
}

// ═══════════════════════════════════════════════════════
// BOOT
// ═══════════════════════════════════════════════════════
document.addEventListener("DOMContentLoaded", () => {

  // Init HMAC signer — silently skipped on plain HTTP, works on HTTPS/localhost
  SIGNER.init().catch(() => {});

  // Build star picker
  buildHalfStarPicker();

  // Set today as min date for booking
  const bd = el("bookDate");
  if (bd) { const today = new Date().toISOString().slice(0, 10); bd.min = today; bd.value = today; }

  // Enter key shortcuts
  el("loginPassword")?.addEventListener("keyup", e => { if (e.key === "Enter") doLogin(); });
  el("loginEmail")?.addEventListener("keyup",    e => { if (e.key === "Enter") doLogin(); });

  // Map resize
  window.addEventListener("resize", () => { if (STATE.map) STATE.map.invalidateSize(); });

  // Backend health check
  fetch(API("/health"))
    .then(r => r.json())
    .then(() => {
      el("connectionBadge").textContent = "● Backend OK";
    })
    .catch(() => {
      el("connectionBadge").textContent = "● Backend Offline";
    });
});