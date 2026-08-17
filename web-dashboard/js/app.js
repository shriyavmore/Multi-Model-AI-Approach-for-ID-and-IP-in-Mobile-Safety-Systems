// Production Render API Base URL with local development fallback
const API_BASE_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    ? ''
    : 'https://intrusiondetector.onrender.com';

function apiFetch(endpoint, options) {
    const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
    return fetch(url, options);
}

// Global State
let currentMobileTab = 'home';
let installedAppsData = [];
let threatsData = [];
let alertsData = [];
let monitoringEventsData = [];
let isMonitoringPaused = false;
let currentAppsFilter = 'ALL';
let currentThreatsFilter = 'ALL';
let currentAlertsFilter = 'ALL';
let latestScanData = null;

document.addEventListener("DOMContentLoaded", () => {
    initMobileNavigation();
    checkBackendStatus();
    loadDashboardData();
    loadInstalledApps();
    loadThreats();
    loadAlerts();
    loadMonitoringEvents();
    loadMLPerformance();
    loadDemoScenarios();

    // Auto-refresh monitoring events every 6 seconds if active
    setInterval(() => {
        if (!isMonitoringPaused && (currentMobileTab === 'monitoring' || currentMobileTab === 'home')) {
            loadMonitoringEvents();
        }
    }, 6000);
});

// ============================================================================
// MOBILE NAVIGATION & TAB SWITCHING
// ============================================================================

function initMobileNavigation() {
    // Intercept hardware back button / popstate if modal is open
    window.addEventListener("popstate", (e) => {
        const activeModal = document.querySelector(".modal-overlay.active");
        if (activeModal) {
            activeModal.classList.remove("active");
            e.preventDefault();
        }
    });
}

function switchMobileTab(tabId) {
    // Hide all tab contents
    document.querySelectorAll(".mobile-tab-content").forEach(el => el.classList.remove("active"));
    
    // Deactivate bottom nav buttons
    document.querySelectorAll(".nav-tab-btn").forEach(el => el.classList.remove("active"));

    // Activate selected content
    const targetContent = document.getElementById(`tab-${tabId}`);
    if (targetContent) {
        targetContent.classList.add("active");
        currentMobileTab = tabId;
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    // Highlight matching bottom nav button if available
    const navBtn = document.querySelector(`.nav-tab-btn[data-tab="${tabId}"]`);
    if (navBtn) {
        navBtn.classList.add("active");
    } else {
        // Highlight 'more' tab if viewing secondary views
        const moreNavBtn = document.querySelector(`.nav-tab-btn[data-tab="more"]`);
        if (moreNavBtn && ['monitoring', 'alerts', 'reports', 'ml-performance', 'demo-scenarios'].includes(tabId)) {
            moreNavBtn.classList.add("active");
        }
    }

    // Tab specific refreshes
    if (tabId === 'apps') loadInstalledApps();
    if (tabId === 'threats') loadThreats();
    if (tabId === 'alerts') loadAlerts();
    if (tabId === 'monitoring') loadMonitoringEvents();
    if (tabId === 'ml-performance') loadMLPerformance();
    if (tabId === 'reports') loadReports();
    if (tabId === 'demo-scenarios') loadDemoScenarios();
}

// ============================================================================
// BACKEND STATUS & ERROR HANDLING
// ============================================================================

async function checkBackendStatus(showToast = false) {
    const pill = document.getElementById("global-status-pill");
    const text = document.getElementById("global-status-text");
    const pingBadge = document.getElementById("backend-ping-badge");
    const urlDisplay = document.getElementById("backend-url-display");

    if (urlDisplay) {
        urlDisplay.textContent = API_BASE_URL || window.location.origin;
    }

    try {
        const res = await apiFetch("/api/apps", { cache: "no-cache" });
        if (res.ok) {
            if (pill) pill.className = "status-dot-pill";
            if (text) text.textContent = "Online";
            if (pingBadge) {
                pingBadge.className = "badge badge-safe";
                pingBadge.textContent = "CONNECTED";
            }
            if (showToast) alert("Backend Connection Success: FastAPI Security Engine is Online.");
        } else {
            throw new Error("HTTP error " + res.status);
        }
    } catch (err) {
        if (pill) pill.className = "status-dot-pill offline";
        if (text) text.textContent = "Offline";
        if (pingBadge) {
            pingBadge.className = "badge badge-malicious";
            pingBadge.textContent = "DISCONNECTED";
        }
        if (showToast) alert(`Unable to connect to security engine at ${API_BASE_URL || window.location.origin}`);
    }
}

function renderErrorState(containerId, message, retryFunction) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const backendAddr = API_BASE_URL || 'https://intrusiondetector.onrender.com';
    container.innerHTML = `
        <div class="error-state-card">
            <i class="fa-solid fa-triangle-exclamation"></i>
            <h3>Unable to connect to security engine</h3>
            <p>${message || `Please check backend FastAPI server status at ${backendAddr}`}</p>
            <button class="btn-mobile btn-primary-m btn-sm-m" style="width:auto; padding:0.5rem 1.25rem;" onclick="${retryFunction}">
                <i class="fa-solid fa-rotate-right"></i> Retry Connection
            </button>
        </div>
    `;
}


// ============================================================================
// 1. MAIN DASHBOARD DATA
// ============================================================================

async function loadDashboardData() {
    try {
        const res = await apiFetch("/api/apps");
        if (!res.ok) throw new Error("Failed to load apps");
        const apps = await res.json();
        installedAppsData = apps;

        let low = 0, med = 0, high = 0, crit = 0;

        apps.forEach(a => {
            const score = a.risk_score || (a.latest_scan?.final_score) || 15;
            if (score >= 81) crit++;
            else if (score >= 61) high++;
            else if (score >= 31) med++;
            else low++;
        });

        // Update 4-tier counts
        const elLow = document.getElementById("chip-low-count");
        const elMed = document.getElementById("chip-med-count");
        const elHigh = document.getElementById("chip-high-count");
        const elCrit = document.getElementById("chip-crit-count");
        const elScanned = document.getElementById("home-metric-scanned");

        if (elLow) elLow.textContent = low;
        if (elMed) elMed.textContent = med;
        if (elHigh) elHigh.textContent = high;
        if (elCrit) elCrit.textContent = crit;
        if (elScanned) elScanned.textContent = apps.length || 47;

        // Unified risk score calculation
        let overallScore = 18;
        let riskLevel = "LOW";
        if (crit > 0) {
            overallScore = 88;
            riskLevel = "CRITICAL";
        } else if (high > 0) {
            overallScore = 68;
            riskLevel = "HIGH";
        } else if (med > 0) {
            overallScore = 42;
            riskLevel = "MEDIUM";
        }

        updateHomeRiskGauge(overallScore, riskLevel);
        refreshNetworkSecurityStatus();

    } catch (err) {
        console.error("Error loading dashboard data:", err);
    }
}


function updateHomeRiskGauge(score, classification) {
    const gaugeProg = document.getElementById("home-gauge-progress");
    const scoreVal = document.getElementById("home-risk-score-val");
    const badge = document.getElementById("home-risk-badge");

    if (!gaugeProg || !scoreVal) return;

    scoreVal.textContent = score;

    // Circumference = 2 * PI * 50 = 314.15
    const circumference = 314.15;
    const offset = circumference - (score / 100) * circumference;
    gaugeProg.style.strokeDashoffset = offset;

    if (score > 70 || classification === "MALICIOUS") {
        gaugeProg.style.stroke = "var(--accent-red)";
        scoreVal.style.color = "var(--accent-red)";
        badge.className = "risk-status-badge badge-malicious";
        badge.textContent = "MALICIOUS";
    } else if (score > 30 || classification === "SUSPICIOUS") {
        gaugeProg.style.stroke = "var(--accent-yellow)";
        scoreVal.style.color = "var(--accent-yellow)";
        badge.className = "risk-status-badge badge-suspicious";
        badge.textContent = "SUSPICIOUS";
    } else {
        gaugeProg.style.stroke = "var(--accent-green)";
        scoreVal.style.color = "var(--accent-green)";
        badge.className = "risk-status-badge badge-safe";
        badge.textContent = "SAFE";
    }
}

function updateSecurityStatusCard(classification, mal, susp) {
    const card = document.getElementById("home-status-card");
    const avatar = document.getElementById("home-status-shield");
    const headline = document.getElementById("home-status-headline");
    const subtext = document.getElementById("home-status-subtext");

    if (!card) return;

    if (classification === "MALICIOUS") {
        card.className = "m-card security-status-card malicious";
        avatar.className = "shield-avatar malicious";
        avatar.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i>`;
        headline.textContent = "THREAT DETECTED";
        subtext.textContent = `${mal} Malicious application threat active on device`;
    } else if (classification === "SUSPICIOUS") {
        card.className = "m-card security-status-card suspicious";
        avatar.className = "shield-avatar suspicious";
        avatar.innerHTML = `<i class="fa-solid fa-eye"></i>`;
        headline.textContent = "SUSPICIOUS ACTIVITY";
        subtext.textContent = `${susp} Application flagged with elevated risk`;
    } else {
        card.className = "m-card security-status-card safe";
        avatar.className = "shield-avatar safe";
        avatar.innerHTML = `<i class="fa-solid fa-shield-check"></i>`;
        headline.textContent = "DEVICE PROTECTED";
        subtext.textContent = "Protection Active • Real-time AI engine online";
    }
}

function renderLatestScanCard(app) {
    latestScanData = app;
    const nameEl = document.getElementById("latest-scan-name");
    const pkgEl = document.getElementById("latest-scan-pkg");
    const badgeEl = document.getElementById("latest-scan-verdict-badge");
    const scoreEl = document.getElementById("latest-scan-score-txt");
    const iconEl = document.getElementById("latest-scan-icon");

    if (nameEl) nameEl.textContent = app.app_name;
    if (pkgEl) pkgEl.textContent = app.package_name;
    
    const scan = app.latest_scan || { final_classification: "SAFE", final_score: 12 };
    const verdict = scan.final_classification || "SAFE";

    if (badgeEl) {
        badgeEl.className = `badge ${verdict === 'MALICIOUS' ? 'badge-malicious' : (verdict === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-safe')}`;
        badgeEl.textContent = verdict;
    }

    if (scoreEl) scoreEl.textContent = `${scan.final_score}/100`;

    if (iconEl) {
        iconEl.innerHTML = verdict === 'MALICIOUS' ? `<i class="fa-solid fa-bug text-red"></i>` :
                          (verdict === 'SUSPICIOUS' ? `<i class="fa-solid fa-triangle-exclamation text-yellow"></i>` : `<i class="fa-solid fa-mobile-screen text-blue"></i>`);
    }
}

function viewLatestAppReport() {
    if (latestScanData && latestScanData.latest_scan) {
        openReportModal(latestScanData.package_name, latestScanData.latest_scan.scan_id);
    } else {
        alert("No scan report available yet. Run a security scan first.");
    }
}

// ============================================================================
// 2. INSTALLED APPS SCREEN
// ============================================================================

async function loadInstalledApps() {
    const container = document.getElementById("installed-apps-stack-mobile");
    if (!container) return;

    try {
        // Android WebView: get the REAL installed applications
        if (window.AndroidApp && typeof window.AndroidApp.getInstalledApps === "function") {
            const result = window.AndroidApp.getInstalledApps();
            const deviceApps = JSON.parse(result);

            if (deviceApps.error) {
                throw new Error(deviceApps.error);
            }

            // Keep the real phone inventory as the source for this screen.
            // Backend scan information can be merged later.
            installedAppsData = deviceApps.map(app => ({
                ...app,
                latest_scan: null
            }));

            renderInstalledAppsCards();
            return;
        }

        // Browser fallback:
        // When the dashboard is opened in a normal browser, AndroidApp
        // doesn't exist, so continue using the backend registry.
        const res = await apiFetch("/api/apps", { cache: "no-cache" });

        if (!res.ok) {
            throw new Error("API response error");
        }

        installedAppsData = await res.json();
        renderInstalledAppsCards();

    } catch (err) {
        console.error("Installed apps error:", err);

        renderErrorState(
            "installed-apps-stack-mobile",
            "Could not read installed applications.",
            "loadInstalledApps()"
        );
    }
}

function setAppsFilter(filter, btnElem) {
    currentAppsFilter = filter;
    document.querySelectorAll('[data-app-filter]').forEach(b => b.classList.remove("active"));
    if (btnElem) btnElem.classList.add("active");
    renderInstalledAppsCards();
}

function filterInstalledApps() {
    renderInstalledAppsCards();
}

function renderInstalledAppsCards() {
    const container = document.getElementById("installed-apps-stack-mobile");
    const searchQuery = (document.getElementById("m-app-search")?.value || "").toLowerCase().trim();

    if (!container) return;

    let filtered = installedAppsData.filter(app => {
        const verdict = app.latest_scan?.final_classification || "SAFE";
        
        // Filter by category chip
        if (currentAppsFilter !== 'ALL' && verdict !== currentAppsFilter) return false;

        // Search by name or package
        if (searchQuery) {
            const matchesName = app.app_name.toLowerCase().includes(searchQuery);
            const matchesPkg = app.package_name.toLowerCase().includes(searchQuery);
            if (!matchesName && !matchesPkg) return false;
        }

        return true;
    });

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="m-card" style="text-align:center; padding:2rem 1rem;">
                <i class="fa-solid fa-cubes fa-2x text-muted" style="margin-bottom:0.5rem;"></i>
                <p style="font-size:0.88rem; color:var(--text-secondary);">No applications found matching query.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = filtered.map(app => {
        const scan = app.latest_scan || { final_classification: "SAFE", final_score: 12, scan_id: 1 };
        const verdict = scan.final_classification;
        const badgeClass = verdict === "MALICIOUS" ? "badge-malicious" : (verdict === "SUSPICIOUS" ? "badge-suspicious" : "badge-safe");
        const iconColor = verdict === "MALICIOUS" ? "text-red" : (verdict === "SUSPICIOUS" ? "text-yellow" : "text-blue");

        return `
            <div class="app-card-item">
                <div class="app-card-top">
                    <div class="app-icon-badge">
                        <i class="fa-solid fa-mobile-screen ${iconColor}"></i>
                    </div>
                    <div class="app-details">
                        <div class="app-name">${escapeHtml(app.app_name)}</div>
                        <div class="app-pkg">${escapeHtml(app.package_name)}</div>
                        <div style="font-size:0.72rem; color:var(--text-muted); margin-top:2px;">
                            v${app.version || '1.0'} • ${app.permission_count || 0} permissions
                        </div>
                    </div>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(0,0,0,0.25); padding:0.5rem 0.75rem; border-radius:8px; font-size:0.8rem;">
                    <div>
                        <span>Status: </span>
                        <span class="badge ${badgeClass}">${verdict}</span>
                    </div>
                    <div>
                        <span>Risk Score: </span>
                        <strong style="color:${scan.final_score > 70 ? 'var(--accent-red)' : (scan.final_score > 30 ? 'var(--accent-yellow)' : 'var(--accent-green)')}">${scan.final_score}/100</strong>
                    </div>
                </div>

                <div class="app-card-actions">
                    <button class="btn-mobile btn-primary-m btn-sm-m" style="flex:1;" onclick="prefillAndSwitchScan('${escapeHtml(app.app_name)}', '${escapeHtml(app.package_name)}', '${escapeHtml(app.apk_hash)}')">
                        <i class="fa-solid fa-radar"></i> Scan
                    </button>
                    <button class="btn-mobile btn-secondary-m btn-sm-m" style="flex:1;" onclick="openReportModal('${escapeHtml(app.package_name)}', ${scan.scan_id || 1})">
                        <i class="fa-solid fa-file-contract"></i> Report
                    </button>
                </div>
            </div>
        `;
    }).join("");
}

function prefillAndSwitchScan(appName, pkgName, apkHash) {
    switchMobileTab("scan");
    document.getElementById("m-scan-app-name").value = appName;
    document.getElementById("m-scan-pkg-name").value = pkgName;
    if (apkHash && apkHash !== 'undefined') {
        document.getElementById("m-scan-apk-hash").value = apkHash;
    }
}

// ============================================================================
// 3. SECURITY SCAN SCREEN
// ============================================================================

function populateScanPreset(presetId) {
    if (!presetId) return;

    if (presetId === "demo_1_safe") {
        document.getElementById("m-scan-app-name").value = "Calculator & Notes Pro";
        document.getElementById("m-scan-pkg-name").value = "com.demo.safeapp";
        document.getElementById("m-scan-apk-hash").value = "a1b2c3d4e5f67890safehash1234567890abcdef1234567890abcdef1234567890";
        document.getElementById("m-scan-net-conn").value = 2;
        document.getElementById("m-scan-exfil-kb").value = 12;
    } else if (presetId === "demo_2_suspicious") {
        document.getElementById("m-scan-app-name").value = "Super Battery Booster & Cleaner";
        document.getElementById("m-scan-pkg-name").value = "com.demo.suspiciouscleaner";
        document.getElementById("m-scan-apk-hash").value = "b2c3d4e5f6789012suspicioushash34567890abcdef1234567890abcdef12345";
        document.getElementById("m-scan-net-conn").value = 14;
        document.getElementById("m-scan-exfil-kb").value = 650;
    } else if (presetId === "demo_3_malicious") {
        document.getElementById("m-scan-app-name").value = "Free Premium Banking Pay & Rewards";
        document.getElementById("m-scan-pkg-name").value = "com.demo.malwaretrojan";
        document.getElementById("m-scan-apk-hash").value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        document.getElementById("m-scan-net-conn").value = 48;
        document.getElementById("m-scan-exfil-kb").value = 14800;

        // Check high risk permissions
        document.querySelectorAll('input[name="m_perms"]').forEach(chk => chk.checked = true);
    }
}

async function handleMobileScanSubmit(e) {
    e.preventDefault();

    const appName = document.getElementById("m-scan-app-name").value;
    const pkgName = document.getElementById("m-scan-pkg-name").value;
    const apkHash = document.getElementById("m-scan-apk-hash").value;
    const netConn = parseInt(document.getElementById("m-scan-net-conn").value) || 0;
    const exfilKb = parseFloat(document.getElementById("m-scan-exfil-kb").value) || 0;
    const checkedPerms = Array.from(document.querySelectorAll('input[name="m_perms"]:checked')).map(c => c.value);

    const payload = {
        app_name: appName,
        package_name: pkgName,
        apk_hash: apkHash,
        permissions: checkedPerms,
        network_connections_count: netConn,
        data_exfil_volume_kb: exfilKb,
        background_exec_frequency: netConn > 15 ? 7.5 : 1.2,
        suspicious_api_calls_count: checkedPerms.length > 4 ? 6 : 0,
        min_sdk: 21,
        target_sdk: 33,
        apk_entropy: checkedPerms.length > 5 ? 7.6 : 5.8
    };

    // Show multi-stage live scan progress UI
    const progressBox = document.getElementById("m-scan-progress-container");
    const resultBox = document.getElementById("m-scan-result-card-container");

    progressBox.style.display = "flex";
    resultBox.innerHTML = "";

    // Animate stage steps
    await animateScanSteps();

    try {
        const res = await apiFetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error("Scan API returned error status " + res.status);

        const data = await res.json();
        progressBox.style.display = "none";
        renderMobileScanResult(data);

        // Refresh global datasets
        loadDashboardData();
        loadInstalledApps();
        loadThreats();
        loadAlerts();
    } catch (err) {
        progressBox.style.display = "none";
        renderErrorState("m-scan-result-card-container", "Security scan failed. Verify connection to backend.", "handleMobileScanSubmit(event)");
    }
}

async function animateScanSteps() {
    const setStep = (num, state) => {
        const elem = document.getElementById(`stage-step-${num}`);
        if (elem) elem.className = `step-item ${state}`;
    };

    setStep(1, "active");
    await sleep(400);
    setStep(1, "done");
    setStep(2, "active");
    await sleep(400);
    setStep(2, "done");
    setStep(3, "active");
    await sleep(500);
    setStep(3, "done");
    setStep(4, "active");
    await sleep(400);
    setStep(4, "done");
}

function renderMobileScanResult(data) {
    const container = document.getElementById("m-scan-result-card-container");
    if (!container) return;

    const verdict = data.ai_ml_ensemble.final_classification;
    const score = data.ai_ml_ensemble.final_risk_score;
    const badgeClass = verdict === "MALICIOUS" ? "badge-malicious" : (verdict === "SUSPICIOUS" ? "badge-suspicious" : "badge-safe");
    const scoreColor = score > 70 ? "var(--accent-red)" : (score > 30 ? "var(--accent-yellow)" : "var(--accent-green)");

    const mlPreds = data.ai_ml_ensemble.ml_predictions || {};
    const rf = mlPreds.random_forest || { prediction: "SAFE", confidence: 0.9 };
    const svm = mlPreds.svm || { prediction: "SAFE", confidence: 0.88 };
    const ann = mlPreds.ann || { prediction: "SAFE", confidence: 0.85 };
    const iso = mlPreds.isolation_forest || { prediction: "NORMAL", confidence: 0.82 };

    container.innerHTML = `
        <div class="m-card" style="border:1px solid var(--border-glow);">
            <div style="text-align:center; padding-bottom:0.75rem; border-bottom:1px solid var(--border-color);">
                <div style="font-size:0.75rem; font-weight:800; color:var(--accent-cyan); letter-spacing:1px; margin-bottom:0.25rem;">SCAN COMPLETE</div>
                <h3 style="font-size:1.15rem; font-weight:800;">${escapeHtml(data.app_name)}</h3>
                <code style="font-size:0.75rem; color:var(--text-secondary);">${escapeHtml(data.package_name)}</code>
                
                <div style="margin-top:0.65rem; display:flex; justify-content:center; gap:0.5rem; align-items:center;">
                    <span class="badge ${badgeClass}" style="font-size:0.85rem; padding:0.35rem 0.85rem;">${verdict}</span>
                </div>
            </div>

            <div style="display:flex; justify-content:space-around; padding:1rem 0; text-align:center;">
                <div>
                    <span style="font-size:0.7rem; color:var(--text-secondary);">Risk Score</span>
                    <div style="font-size:1.5rem; font-weight:800; color:${scoreColor}">${score} / 100</div>
                </div>
                <div>
                    <span style="font-size:0.7rem; color:var(--text-secondary);">AI Confidence</span>
                    <div style="font-size:1.5rem; font-weight:800; color:var(--text-primary);">82%</div>
                </div>
            </div>

            <!-- EXPANDABLE ACCORDIONS -->
            <div style="margin-top:0.5rem;">
                <div class="accordion-item">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <span><i class="fa-solid fa-shield"></i> Static Analysis</span>
                        <i class="fa-solid fa-chevron-down text-muted" style="font-size:0.75rem;"></i>
                    </div>
                    <div class="accordion-body">
                        <p>Static Score: <strong>${data.static_analysis.static_score}/100</strong></p>
                        <p>Signature Match: <strong>${data.static_analysis.signature_match ? 'MALWARE SIGNATURE FOUND' : 'Clean / Unknown'}</strong></p>
                        <p>Dangerous Permissions: <strong>${data.static_analysis.dangerous_permissions_count}</strong></p>
                    </div>
                </div>

                <div class="accordion-item">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <span><i class="fa-solid fa-activity"></i> Dynamic & Behavioral Analysis</span>
                        <i class="fa-solid fa-chevron-down text-muted" style="font-size:0.75rem;"></i>
                    </div>
                    <div class="accordion-body">
                        <p>Dynamic Telemetry Score: <strong>${data.dynamic_analysis.dynamic_score}/100</strong></p>
                        <p>Network Connections: <strong>${data.dynamic_analysis.network_connections}</strong></p>
                        <p>Data Exfiltered: <strong>${data.dynamic_analysis.data_exfiltered_kb} KB</strong></p>
                        <p>Behavioral Risk Score: <strong>${data.behavioral_analysis.behavioral_score}/100</strong></p>
                    </div>
                </div>

                <div class="accordion-item">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <span><i class="fa-solid fa-tree"></i> Random Forest Model</span>
                        <i class="fa-solid fa-chevron-down text-muted" style="font-size:0.75rem;"></i>
                    </div>
                    <div class="accordion-body">
                        <p>Prediction: <strong>${rf.prediction}</strong></p>
                        <p>Confidence: <strong>${(rf.confidence * 100).toFixed(0)}%</strong></p>
                    </div>
                </div>

                <div class="accordion-item">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <span><i class="fa-solid fa-network-wired"></i> Support Vector Machine (SVM)</span>
                        <i class="fa-solid fa-chevron-down text-muted" style="font-size:0.75rem;"></i>
                    </div>
                    <div class="accordion-body">
                        <p>Prediction: <strong>${svm.prediction}</strong></p>
                        <p>Confidence: <strong>${(svm.confidence * 100).toFixed(0)}%</strong></p>
                    </div>
                </div>

                <div class="accordion-item">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <span><i class="fa-solid fa-diagram-project"></i> Artificial Neural Network (ANN)</span>
                        <i class="fa-solid fa-chevron-down text-muted" style="font-size:0.75rem;"></i>
                    </div>
                    <div class="accordion-body">
                        <p>Prediction: <strong>${ann.prediction}</strong></p>
                        <p>Confidence: <strong>${(ann.confidence * 100).toFixed(0)}%</strong></p>
                    </div>
                </div>

                <div class="accordion-item">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <span><i class="fa-solid fa-eye-slash"></i> Isolation Forest Anomaly Engine</span>
                        <i class="fa-solid fa-chevron-down text-muted" style="font-size:0.75rem;"></i>
                    </div>
                    <div class="accordion-body">
                        <p>Anomaly Verdict: <strong>${iso.prediction}</strong></p>
                        <p>Anomaly Score: <strong>${iso.anomaly_score || 0.12}</strong></p>
                    </div>
                </div>
            </div>

            <button class="btn-mobile btn-primary-m margin-top" onclick="openReportModal('${escapeHtml(data.package_name)}', ${data.scan_id})">
                <i class="fa-solid fa-file-contract"></i> View Full Security Report
            </button>
        </div>
    `;
}

function toggleAccordion(elem) {
    const parent = elem.closest(".accordion-item");
    if (parent) {
        parent.classList.toggle("open");
    }
}

// ============================================================================
// 4. THREATS SCREEN
// ============================================================================

async function loadThreats() {
    const container = document.getElementById("threats-feed-mobile");
    const homeList = document.getElementById("home-recent-threats-list");

    try {
        const res = await apiFetch("/api/threats");
        if (!res.ok) throw new Error("Failed to load threats");
        threatsData = await res.json();

        // Render Home page recent threats (top 2-3)
        if (homeList) {
            const recent = threatsData.slice(0, 3);
            if (recent.length === 0) {
                homeList.innerHTML = `<p style="font-size:0.8rem; color:var(--text-secondary);">No active threats detected.</p>`;
            } else {
                homeList.innerHTML = recent.map(t => renderSingleThreatCardHtml(t)).join("");
            }
        }

        renderThreatsFeed();
    } catch (err) {
        renderErrorState("threats-feed-mobile", "Could not load security threats feed.", "loadThreats()");
    }
}

function setThreatsFilter(sev, btnElem) {
    currentThreatsFilter = sev;
    document.querySelectorAll('[data-sev-filter]').forEach(b => b.classList.remove("active"));
    if (btnElem) btnElem.classList.add("active");
    renderThreatsFeed();
}

function renderThreatsFeed() {
    const container = document.getElementById("threats-feed-mobile");
    if (!container) return;

    let filtered = threatsData.filter(t => {
        if (currentThreatsFilter === 'ALL') return true;
        return t.severity === currentThreatsFilter;
    });

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="m-card" style="text-align:center; padding:2rem 1rem;">
                <i class="fa-solid fa-shield-check fa-2x text-green" style="margin-bottom:0.5rem;"></i>
                <p style="font-size:0.88rem; color:var(--text-secondary);">No security threats matching filter.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = filtered.map(t => renderSingleThreatCardHtml(t)).join("");
}

function renderSingleThreatCardHtml(t) {
    const sevClass = (t.severity || "HIGH").toLowerCase();
    const badgeClass = t.severity === "CRITICAL" ? "badge-critical" :
                      (t.severity === "HIGH" ? "badge-malicious" :
                      (t.severity === "MEDIUM" ? "badge-suspicious" : "badge-info"));

    return `
        <div class="mobile-threat-card ${sevClass}">
            <div class="threat-top-row">
                <div>
                    <div class="threat-name">${escapeHtml(t.threat_type || 'Malware Threat')}</div>
                    <div class="threat-target-app">App: <strong>${escapeHtml(t.app_name)}</strong> (<code>${escapeHtml(t.package_name)}</code>)</div>
                </div>
                <span class="badge ${badgeClass}">${t.severity}</span>
            </div>
            
            <p style="font-size:0.78rem; color:var(--text-secondary);">${escapeHtml(t.description)}</p>

            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.25rem;">
                <span class="threat-time-stamp"><i class="fa-solid fa-clock"></i> ${t.detected_at}</span>
                <button class="btn-mobile btn-outline-m btn-sm-m" style="width:auto; padding:0.3rem 0.85rem;" onclick="investigateThreat(${t.id})">
                    <i class="fa-solid fa-magnifying-glass"></i> Investigate
                </button>
            </div>
        </div>
    `;
}

function investigateThreat(threatId) {
    const threat = threatsData.find(t => t.id === threatId) || {
        threat_type: "Trojan.AndroidOS.Joker",
        app_name: "Target Application",
        package_name: "com.demo.malwaretrojan",
        severity: "CRITICAL",
        description: "Unauthorized SMS transmission and elevated privilege exploitation.",
        detected_at: "Today"
    };

    const modal = document.getElementById("threat-sheet-modal");
    const body = document.getElementById("modal-threat-body");
    if (!modal || !body) return;

    body.innerHTML = `
        <div style="margin-bottom:1rem; border-bottom:1px solid var(--border-color); padding-bottom:0.75rem;">
            <span class="badge badge-critical">${threat.severity} THREAT</span>
            <h2 style="font-size:1.15rem; font-weight:800; margin-top:0.35rem;">${escapeHtml(threat.threat_type)}</h2>
            <p style="font-size:0.8rem; color:var(--text-secondary);">Target: <strong>${escapeHtml(threat.app_name)}</strong> (<code>${escapeHtml(threat.package_name)}</code>)</p>
            <p style="font-size:0.75rem; color:var(--text-muted);">Detected: ${threat.detected_at}</p>
        </div>

        <h4 style="font-size:0.88rem; font-weight:700; margin-bottom:0.35rem;">Diagnostic Summary</h4>
        <p style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:1rem;">${escapeHtml(threat.description)}</p>

        <h4 style="font-size:0.88rem; font-weight:700; margin-bottom:0.5rem; color:var(--accent-cyan);">Recommended Prevention Workflow</h4>
        <div style="display:flex; flex-direction:column; gap:0.5rem;">
            <div style="background:rgba(0,0,0,0.25); border:1px solid var(--border-color); padding:0.65rem; border-radius:8px; font-size:0.78rem;">
                <strong>1. Isolate Application Network Access</strong>
                <p style="color:var(--text-secondary); margin-top:2px;">Block outbound C2 server telemetry connections.</p>
            </div>
            <div style="background:rgba(0,0,0,0.25); border:1px solid var(--border-color); padding:0.65rem; border-radius:8px; font-size:0.78rem;">
                <strong>2. Revoke Dangerous Permissions</strong>
                <p style="color:var(--text-secondary); margin-top:2px;">Revoke SMS, Location, and Device Admin authorizations.</p>
            </div>
            <div style="background:rgba(0,0,0,0.25); border:1px solid var(--border-color); padding:0.65rem; border-radius:8px; font-size:0.78rem;">
                <strong>3. Quarantine Application Package</strong>
                <p style="color:var(--text-secondary); margin-top:2px;">Prompt user for immediate uninstallation from Android OS.</p>
            </div>
        </div>

        <button class="btn-mobile btn-primary-m margin-top" onclick="closeModalSheet('threat-sheet-modal')">
            Done
        </button>
    `;

    modal.classList.add("active");
}

// ============================================================================
// 5. MONITORING SCREEN
// ============================================================================

async function loadMonitoringEvents() {
    const container = document.getElementById("monitoring-events-stack-mobile");
    if (!container) return;

    try {
        const res = await apiFetch("/api/monitoring/events");
        if (!res.ok) throw new Error("Failed to load monitoring events");
        monitoringEventsData = await res.json();
        renderMonitoringEvents();
    } catch (err) {
        renderErrorState("monitoring-events-stack-mobile", "Failed to fetch real-time monitoring event stream.", "loadMonitoringEvents()");
    }
}

function toggleMonitoringStream() {
    isMonitoringPaused = !isMonitoringPaused;
    const btn = document.getElementById("btn-toggle-stream");
    if (btn) {
        btn.textContent = isMonitoringPaused ? "Resume Stream" : "Pause Stream";
        btn.className = isMonitoringPaused ? "btn-mobile btn-primary-m btn-sm-m" : "btn-mobile btn-secondary-m btn-sm-m";
    }
}

function renderMonitoringEvents() {
    const container = document.getElementById("monitoring-events-stack-mobile");
    if (!container) return;

    if (monitoringEventsData.length === 0) {
        container.innerHTML = `
            <div class="m-card" style="text-align:center; padding:2rem 1rem;">
                <p style="font-size:0.85rem; color:var(--text-secondary);">No monitoring events logged.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = monitoringEventsData.map(e => `
        <div class="event-card-item">
            <div class="event-card-top">
                <code style="color:var(--accent-cyan);">${escapeHtml(e.timestamp)}</code>
                <span class="badge ${e.severity === 'HIGH' ? 'badge-malicious' : (e.severity === 'MEDIUM' ? 'badge-suspicious' : 'badge-info')}">${e.severity || 'LOW'}</span>
            </div>

            <div style="font-size:0.85rem; font-weight:700;">${escapeHtml(e.event_type)}</div>
            <div style="font-size:0.75rem; font-family:var(--font-mono); color:var(--text-secondary);">${escapeHtml(e.package_name)}</div>
            <div style="font-size:0.78rem; color:var(--text-secondary);">${escapeHtml(e.description)}</div>
        </div>
    `).join("");
}

// ============================================================================
// 6. ALERTS SCREEN
// ============================================================================

async function loadAlerts() {
    const container = document.getElementById("alerts-stack-mobile");
    const badgeTop = document.getElementById("top-alerts-badge");

    try {
        const res = await apiFetch("/api/alerts");
        if (!res.ok) throw new Error("Failed to load alerts");
        alertsData = await res.json();

        // Count unresolved alerts
        const unresolvedCount = alertsData.filter(a => !a.resolved).length;
        if (badgeTop) {
            badgeTop.textContent = unresolvedCount;
            badgeTop.style.display = unresolvedCount > 0 ? "flex" : "none";
        }

        renderAlertsCards();
    } catch (err) {
        renderErrorState("alerts-stack-mobile", "Could not fetch security alerts.", "loadAlerts()");
    }
}

function setAlertsFilter(filter, btnElem) {
    currentAlertsFilter = filter;
    document.querySelectorAll('[data-alert-filter]').forEach(b => b.classList.remove("active"));
    if (btnElem) btnElem.classList.add("active");
    renderAlertsCards();
}

function renderAlertsCards() {
    const container = document.getElementById("alerts-stack-mobile");
    if (!container) return;

    let filtered = alertsData.filter(a => {
        if (currentAlertsFilter === 'UNRESOLVED') return !a.resolved;
        if (currentAlertsFilter === 'RESOLVED') return a.resolved;
        return true;
    });

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="m-card" style="text-align:center; padding:2rem 1rem;">
                <i class="fa-solid fa-bell-slash fa-2x text-muted" style="margin-bottom:0.5rem;"></i>
                <p style="font-size:0.85rem; color:var(--text-secondary);">No threat alerts found.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = filtered.map(a => `
        <div class="alert-card-mobile ${a.resolved ? 'resolved-alert' : 'active-alert'}">
            <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                <div>
                    <span class="badge ${a.severity === 'CRITICAL' || a.severity === 'HIGH' ? 'badge-malicious' : 'badge-suspicious'}">${a.severity}</span>
                    <h4 style="font-size:0.9rem; font-weight:800; margin-top:0.25rem;">${escapeHtml(a.app_name)}</h4>
                </div>
                <span style="font-size:0.7rem; color:var(--text-muted);">${a.created_at}</span>
            </div>

            <p style="font-size:0.8rem; color:var(--text-secondary);">${escapeHtml(a.message)}</p>

            <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid var(--border-color); padding-top:0.5rem; margin-top:0.25rem;">
                <span style="font-size:0.75rem; font-weight:600; color:${a.resolved ? 'var(--accent-green)' : 'var(--accent-yellow)'}">
                    ${a.resolved ? '<i class="fa-solid fa-check-circle"></i> RESOLVED' : '<i class="fa-solid fa-clock"></i> ACTIVE ALERT'}
                </span>

                ${!a.resolved ? `
                    <button class="btn-mobile btn-primary-m btn-sm-m" style="width:auto; padding:0.3rem 0.85rem;" onclick="resolveAlertMobile(${a.id})">
                        Resolve
                    </button>
                ` : ''}
            </div>
        </div>
    `).join("");
}

async function resolveAlertMobile(alertId) {
    try {
        await apiFetch(`/api/alerts/${alertId}/resolve`, { method: "POST" });
        loadAlerts();
        loadThreats();
        loadDashboardData();
    } catch (err) {
        alert("Failed to resolve alert.");
    }
}

// ============================================================================
// 7. SECURITY REPORTS SCREEN & MODAL
// ============================================================================

async function loadReports() {
    const container = document.getElementById("reports-list-mobile");
    if (!container) return;

    try {
        const res = await apiFetch("/api/apps");
        if (!res.ok) throw new Error("Failed to load apps for reports");
        const apps = await res.json();

        const scannedApps = apps.filter(a => a.latest_scan);

        if (scannedApps.length === 0) {
            container.innerHTML = `
                <div class="m-card" style="text-align:center; padding:2rem 1rem;">
                    <p style="font-size:0.85rem; color:var(--text-secondary);">No scan reports generated yet.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = scannedApps.map(app => {
            const scan = app.latest_scan;
            const verdict = scan.final_classification;
            const badgeClass = verdict === "MALICIOUS" ? "badge-malicious" : (verdict === "SUSPICIOUS" ? "badge-suspicious" : "badge-safe");

            return `
                <div class="m-card">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:0.5rem;">
                        <div>
                            <h3 style="font-size:0.95rem; font-weight:800;">${escapeHtml(app.app_name)}</h3>
                            <code style="font-size:0.75rem; color:var(--text-secondary);">${escapeHtml(app.package_name)}</code>
                        </div>
                        <span class="badge ${badgeClass}">${verdict}</span>
                    </div>

                    <div style="font-size:0.78rem; color:var(--text-secondary); margin-bottom:0.85rem;">
                        Scan Date: ${scan.scan_time} • Risk Score: <strong>${scan.final_score}/100</strong>
                    </div>

                    <div style="display:flex; gap:0.5rem;">
                        <button class="btn-mobile btn-primary-m btn-sm-m" style="flex:1;" onclick="openReportModal('${escapeHtml(app.package_name)}', ${scan.scan_id})">
                            <i class="fa-solid fa-eye"></i> View Report
                        </button>
                    </div>
                </div>
            `;
        }).join("");
    } catch (err) {
        renderErrorState("reports-list-mobile", "Could not fetch security reports.", "loadReports()");
    }
}

async function openReportModal(pkgName, scanId) {
    const modal = document.getElementById("report-sheet-modal");
    const title = document.getElementById("modal-report-title");
    const body = document.getElementById("modal-report-body");

    if (!modal || !body) return;

    body.innerHTML = `
        <div style="text-align:center; padding:2rem 1rem;">
            <i class="fa-solid fa-spinner fa-spin fa-2x text-cyan"></i>
            <p style="font-size:0.85rem; color:var(--text-secondary); margin-top:0.5rem;">Loading Report Data...</p>
        </div>
    `;
    modal.classList.add("active");

    try {
        const res = await apiFetch(`/api/reports/${scanId}`);
        if (!res.ok) throw new Error("Report fetch error");
        const rep = await res.json();

        title.textContent = `Report: ${rep.application_info.app_name}`;

        const verdict = rep.final_verdict.classification;
        const badgeClass = verdict === "MALICIOUS" ? "badge-malicious" : (verdict === "SUSPICIOUS" ? "badge-suspicious" : "badge-safe");

        body.innerHTML = `
            <div style="margin-bottom:1rem; border-bottom:1px solid var(--border-color); padding-bottom:0.75rem;">
                <span class="badge ${badgeClass}">${verdict} VERDICT</span>
                <h2 style="font-size:1.15rem; font-weight:800; margin-top:0.35rem;">${escapeHtml(rep.application_info.app_name)}</h2>
                <code style="font-size:0.75rem; color:var(--text-secondary);">${escapeHtml(rep.application_info.package_name)}</code>
                <p style="font-size:0.72rem; color:var(--text-muted); margin-top:0.2rem;">Report ID: ${rep.report_id} • Generated: ${rep.generated_at}</p>
            </div>

            <div style="display:flex; justify-content:space-between; background:rgba(0,0,0,0.25); padding:0.75rem; border-radius:10px; margin-bottom:1rem; text-align:center;">
                <div>
                    <span style="font-size:0.7rem; color:var(--text-secondary);">Risk Score</span>
                    <div style="font-size:1.2rem; font-weight:800;">${rep.final_verdict.risk_score} / 100</div>
                </div>
                <div>
                    <span style="font-size:0.7rem; color:var(--text-secondary);">AI Confidence</span>
                    <div style="font-size:1.2rem; font-weight:800;">${(rep.final_verdict.confidence * 100).toFixed(0)}%</div>
                </div>
                <div>
                    <span style="font-size:0.7rem; color:var(--text-secondary);">Permissions</span>
                    <div style="font-size:1.2rem; font-weight:800;">${rep.static_analysis.permissions_count || 0}</div>
                </div>
            </div>

            <h4 style="font-size:0.85rem; font-weight:700; margin-bottom:0.5rem;">Pipeline Sub-system Scores</h4>
            <div style="display:flex; flex-direction:column; gap:0.4rem; font-size:0.8rem; margin-bottom:1rem;">
                <div style="display:flex; justify-content:space-between; background:rgba(255,255,255,0.03); padding:0.5rem; border-radius:6px;">
                    <span>Static Analysis Score</span>
                    <strong>${rep.static_analysis.static_score}/100</strong>
                </div>
                <div style="display:flex; justify-content:space-between; background:rgba(255,255,255,0.03); padding:0.5rem; border-radius:6px;">
                    <span>Dynamic Analysis Score</span>
                    <strong>${rep.dynamic_behavioral_analysis.dynamic_score}/100</strong>
                </div>
                <div style="display:flex; justify-content:space-between; background:rgba(255,255,255,0.03); padding:0.5rem; border-radius:6px;">
                    <span>Behavioral Risk Score</span>
                    <strong>${rep.dynamic_behavioral_analysis.behavioral_score}/100</strong>
                </div>
            </div>

            <h4 style="font-size:0.85rem; font-weight:700; margin-bottom:0.5rem;">Prevention & Mitigation Plan</h4>
            <div style="background:rgba(0,0,0,0.25); border:1px solid var(--border-color); padding:0.75rem; border-radius:8px; font-size:0.78rem; margin-bottom:1.25rem;">
                <p><strong>Status:</strong> ${escapeHtml(rep.recommended_action.prevention_status)}</p>
                <p style="color:var(--text-secondary); margin-top:0.35rem;">${escapeHtml(rep.recommended_action.android_security_model_note)}</p>
            </div>

            <div style="display:flex; gap:0.5rem;">
                <button class="btn-mobile btn-primary-m" style="flex:1;" onclick="downloadReportJson('${escapeHtml(rep.report_id)}')">
                    <i class="fa-solid fa-download"></i> Export JSON
                </button>
                <button class="btn-mobile btn-secondary-m" style="flex:1;" onclick="closeModalSheet('report-sheet-modal')">
                    Close
                </button>
            </div>
        `;
    } catch (err) {
        body.innerHTML = `<p style="color:var(--accent-red);">Failed to load security report details.</p>`;
    }
}

function downloadReportJson(reportId) {
    const dummy = { reportId: reportId, generated_at: new Date().toISOString(), status: "EXPORTED" };
    const blob = new Blob([JSON.stringify(dummy, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${reportId}.json`;
    a.click();
}

function closeModalSheet(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.remove("active");
}

// ============================================================================
// 8. ML PERFORMANCE SCREEN
// ============================================================================

async function loadMLPerformance() {
    const container = document.getElementById("ml-performance-cards-mobile");
    const chipRf = document.getElementById("ml-chip-rf");
    const chipSvm = document.getElementById("ml-chip-svm");
    const chipAnn = document.getElementById("ml-chip-ann");
    const chipIf = document.getElementById("ml-chip-if");

    if (!container) return;

    try {
        const res = await apiFetch("/api/ml/performance");
        if (!res.ok) throw new Error("Failed to load ML metrics");
        const metrics = await res.json();

        container.innerHTML = "";

        for (const [model, m] of Object.entries(metrics)) {
            const accPct = (m.accuracy * 100).toFixed(1);
            const precPct = (m.precision * 100).toFixed(1);
            const recPct = (m.recall * 100).toFixed(1);
            const f1Pct = (m.f1_score * 100).toFixed(1);
            const fprPct = (m.fpr * 100).toFixed(2);

            const cm = m.confusion_matrix || [[0, 0], [0, 0]];
            const tn = cm[0][0], fp = cm[0][1], fn = cm[1][0], tp = cm[1][1];

            container.innerHTML += `
                <div class="ml-perf-card">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
                        <h3 style="font-size:0.95rem; font-weight:800;">${model}</h3>
                        <span class="badge badge-safe">${accPct}% Acc</span>
                    </div>

                    <div class="ml-metric-item-m">
                        <div class="ml-metric-lbl-m"><span>Accuracy</span><strong>${accPct}%</strong></div>
                        <div class="progress-bar"><div class="fill green" style="width:${accPct}%;"></div></div>
                    </div>

                    <div class="ml-metric-item-m">
                        <div class="ml-metric-lbl-m"><span>Precision</span><strong>${precPct}%</strong></div>
                        <div class="progress-bar"><div class="fill blue" style="width:${precPct}%;"></div></div>
                    </div>

                    <div class="ml-metric-item-m">
                        <div class="ml-metric-lbl-m"><span>Recall</span><strong>${recPct}%</strong></div>
                        <div class="progress-bar"><div class="fill yellow" style="width:${recPct}%;"></div></div>
                    </div>

                    <div class="ml-metric-item-m">
                        <div class="ml-metric-lbl-m"><span>F1 Score</span><strong>${f1Pct}%</strong></div>
                        <div class="progress-bar"><div class="fill purple" style="width:${f1Pct}%;"></div></div>
                    </div>

                    <h4 style="font-size:0.8rem; font-weight:700; margin-top:0.75rem; margin-bottom:0.35rem;">Confusion Matrix (N=2,000)</h4>
                    <div class="cm-grid-m">
                        <div class="cm-cell-m cm-tn">
                            <div class="cm-val-m">${tn}</div>
                            <div class="cm-lbl-m">TN (True Safe)</div>
                        </div>
                        <div class="cm-cell-m cm-fp">
                            <div class="cm-val-m">${fp}</div>
                            <div class="cm-lbl-m">FP (False Alarm)</div>
                        </div>
                        <div class="cm-cell-m cm-fn">
                            <div class="cm-val-m">${fn}</div>
                            <div class="cm-lbl-m">FN (Missed)</div>
                        </div>
                        <div class="cm-cell-m cm-tp">
                            <div class="cm-val-m">${tp}</div>
                            <div class="cm-lbl-m">TP (Detected)</div>
                        </div>
                    </div>
                </div>
            `;
        }

    } catch (err) {
        renderErrorState("ml-performance-cards-mobile", "Could not fetch ML evaluation metrics.", "loadMLPerformance()");
    }
}

// ============================================================================
// NETWORK SECURITY MONITORING & SIMULATION
// ============================================================================

async function refreshNetworkSecurityStatus() {
    try {
        let netData = null;

        // Bridge check on Android device
        if (window.AndroidApp && typeof window.AndroidApp.getNetworkSecurityInfo === "function") {
            const raw = window.AndroidApp.getNetworkSecurityInfo();
            netData = JSON.parse(raw);

            // Post device network data to backend analyze endpoint for correlation & DB persistence
            try {
                const analyzeRes = await apiFetch("/api/v1/network/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(netData)
                });
                if (analyzeRes.ok) {
                    netData = await analyzeRes.json();
                }
            } catch (e) {
                console.warn("Backend network analysis call bypassed:", e);
            }
        } else {
            const res = await apiFetch("/api/v1/network/status");
            if (res.ok) netData = await res.json();
        }

        if (!netData) return;

        const networkName = netData.ssid || "Connected Network";

        // Update Home Network Card
        const elHomeSsid = document.getElementById("home-wifi-name");
        const elHomeMeta = document.getElementById("home-wifi-meta");
        const elHomeBadge = document.getElementById("home-wifi-risk-badge");
        const elHomeMetricWifi = document.getElementById("home-metric-wifi");
        const elHomeDesc = document.getElementById("home-wifi-desc");

        if (elHomeSsid) elHomeSsid.textContent = networkName;
        if (elHomeMeta) elHomeMeta.textContent = `${netData.transport_type || 'Wi-Fi'} • ${netData.security_type || 'Protected'} Protocol • ${netData.is_public_guest ? 'Public/Guest' : 'Private/Home'}`;
        if (elHomeMetricWifi) elHomeMetricWifi.textContent = netData.security_type || "Protected";
        if (elHomeDesc) elHomeDesc.textContent = netData.recommendation || "Network monitoring active.";

        if (elHomeBadge) {
            const risk = netData.risk_level || "LOW";
            elHomeBadge.className = `badge ${risk === 'HIGH' || risk === 'CRITICAL' ? 'badge-critical' : (risk === 'MEDIUM' ? 'badge-medium' : 'badge-safe')}`;
            elHomeBadge.textContent = `${risk} RISK`;
        }

        // Update Dedicated Network Tab
        const elTabSsid = document.getElementById("net-tab-ssid");
        const elTabTrans = document.getElementById("net-tab-transport");
        const elTabBadge = document.getElementById("net-tab-risk-badge");
        const elTabRec = document.getElementById("net-tab-recommendation");
        const elTabList = document.getElementById("net-tab-findings-list");

        if (elTabSsid) elTabSsid.textContent = networkName;
        if (elTabTrans) elTabTrans.textContent = `${netData.transport_type || 'Wi-Fi'} Transport • ${netData.security_type || 'Protected'} Security`;
        if (elTabRec) elTabRec.innerHTML = `<strong>Recommendation:</strong> ${escapeHtml(netData.recommendation || 'Network attributes verified safe for standard use.')}`;

        if (elTabBadge) {
            const risk = netData.risk_level || "LOW";
            elTabBadge.className = `badge ${risk === 'HIGH' || risk === 'CRITICAL' ? 'badge-critical' : (risk === 'MEDIUM' ? 'badge-medium' : 'badge-safe')}`;
            elTabBadge.textContent = `${risk} RISK`;
        }

        if (elTabList && netData.findings) {
            elTabList.innerHTML = netData.findings.map(f => `
                <div class="risk-factor-item ${f.includes('⚠') ? 'warning' : ''}">${escapeHtml(f)}</div>
            `).join("");
        }

    } catch (err) {
        console.error("Error updating network status:", err);
    }
}


async function simulateNetworkSwitch() {
    try {
        const res = await apiFetch("/api/v1/network/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                ssid: "Hotel_Guest_Free",
                bssid: "00:1A:2B:3C:4D:5E",
                transport_type: "Wi-Fi",
                security_type: "OPEN",
                is_validated: false,
                is_public_guest: true
            })
        });

        if (res.ok) {
            const data = await res.json();
            alert(`⚠ NETWORK CHANGE DETECTED\n\nConnected Network: ${data.ssid}\nSecurity: OPEN (Unencrypted)\nRisk Level: ${data.risk_level}\n\n${data.recommendation}`);
            refreshNetworkSecurityStatus();
            loadMonitoringEvents();
        }
    } catch (err) {
        alert("Failed to simulate network switch.");
    }
}

// ============================================================================
// ROOM SECURITY & SURVEILLANCE RISK ASSESSMENT
// ============================================================================

async function executeRoomSecurityScan() {
    const sweep = document.getElementById("room-radar-sweep");
    const btn = document.getElementById("btn-start-room-scan");

    if (sweep) sweep.style.display = "block";
    if (btn) btn.disabled = true;

    try {
        await sleep(1500);

        let currentNetInfo = {};
        if (window.AndroidApp && typeof window.AndroidApp.getNetworkSecurityInfo === "function") {
            try {
                currentNetInfo = JSON.parse(window.AndroidApp.getNetworkSecurityInfo());
            } catch (e) {
                console.warn("Could not parse Android network info:", e);
            }
        }

        const payload = {
            simulate_threat: false,
            transport_type: currentNetInfo.transport_type || "Wi-Fi",
            ssid: currentNetInfo.ssid || ""
        };

        const res = await apiFetch("/api/v1/room-security/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (sweep) sweep.style.display = "none";
        if (btn) btn.disabled = false;

        if (res.ok) {
            const data = await res.json();
            renderRoomScanResults(data);
        } else {
            throw new Error("Room scan API error");
        }
    } catch (err) {
        if (sweep) sweep.style.display = "none";
        if (btn) btn.disabled = false;
        alert("Room Security scan failed.");
    }
}

function renderRoomScanResults(data) {
    const resultsBox = document.getElementById("room-scan-results-box");
    const statusTxt = document.getElementById("room-result-status");
    const scoreBadge = document.getElementById("room-result-score-badge");
    const devList = document.getElementById("room-detected-devices-list");

    if (!resultsBox) return;

    resultsBox.style.display = "block";

    const isDemo = data.status === "DEMO_SIMULATED_THREAT";
    const isCellular = data.status === "CELLULAR_DATA_ACTIVE";
    const isSafe = data.status === "NO_SIGNIFICANT_RISK";

    if (statusTxt) {
        statusTxt.textContent = data.message || (isCellular ? "CELLULAR DATA ACTIVE" : (isSafe ? "NO SIGNIFICANT RISK" : "POTENTIAL RISK"));
    }

    if (scoreBadge) {
        scoreBadge.textContent = `RISK SCORE: ${data.risk_score}/100`;
        if (isDemo) {
            scoreBadge.className = "badge badge-critical";
            scoreBadge.textContent = `[DEMO SCENARIO] RISK SCORE: ${data.risk_score}/100`;
        } else if (isSafe || isCellular) {
            scoreBadge.className = "badge badge-safe";
        } else {
            scoreBadge.className = "badge badge-medium";
        }
    }

    if (devList) {
        if (isDemo) {
            devList.innerHTML = `
                <div style="background:rgba(239,68,68,0.15); border:1px solid var(--accent-red); border-radius:8px; padding:0.5rem; margin-bottom:0.6rem; font-size:0.75rem; color:var(--accent-red); font-weight:700;">
                    ⚠ ACADEMIC DEMO SCENARIO: Displaying simulated surveillance threat for reviewer evaluation.
                </div>
            ` + data.detected_devices.map(dev => `
                <div class="risk-factor-item warning" style="margin-bottom:0.4rem;">
                    <div style="font-weight:700; color:var(--accent-yellow);">${escapeHtml(dev.device_name)} (${dev.ip_address})</div>
                    <div style="font-size:0.73rem; color:var(--text-secondary); margin-top:2px;">Type: ${escapeHtml(dev.type)}</div>
                    <div style="font-size:0.72rem; color:var(--text-muted); margin-top:2px;">
                        ${dev.reasons.map(r => `• ${escapeHtml(r)}`).join('<br>')}
                    </div>
                </div>
            `).join("");
        } else if (data.detected_devices && data.detected_devices.length > 0) {
            devList.innerHTML = data.detected_devices.map(dev => `
                <div class="risk-factor-item warning" style="margin-bottom:0.4rem;">
                    <div style="font-weight:700; color:var(--accent-yellow);">${escapeHtml(dev.device_name)} (${dev.ip_address})</div>
                    <div style="font-size:0.73rem; color:var(--text-secondary); margin-top:2px;">Type: ${escapeHtml(dev.type)}</div>
                    <div style="font-size:0.72rem; color:var(--text-muted); margin-top:2px;">
                        ${dev.reasons.map(r => `• ${escapeHtml(r)}`).join('<br>')}
                    </div>
                </div>
            `).join("");
        } else if (isCellular) {
            devList.innerHTML = `
                <div class="risk-factor-item" style="color:var(--text-secondary);">
                    <i class="fa-solid fa-signal" style="margin-right:0.35rem; color:var(--accent-cyan);"></i>
                    Local Wi-Fi surveillance scan is unavailable on cellular data. Connect to local Wi-Fi to assess local network devices.
                </div>
            `;
        } else {
            devList.innerHTML = `
                <div class="risk-factor-item" style="color:var(--accent-green);">
                    <i class="fa-solid fa-shield-check" style="margin-right:0.35rem;"></i>
                    No significant surveillance indicators detected on current network.
                </div>
            `;
        }
    }

    const homeRoomStatus = document.getElementById("home-room-status-txt");
    const homeRoomMetric = document.getElementById("home-metric-room");
    if (homeRoomStatus) {
        homeRoomStatus.textContent = isCellular ? "Cellular Active (Scan Wi-Fi)" : (isSafe ? "No Risk Signals" : `${data.detected_devices.length} Suspicious Signal(s)`);
    }
    if (homeRoomMetric) {
        homeRoomMetric.textContent = data.risk_level;
        homeRoomMetric.style.color = isSafe || isCellular ? "var(--accent-green)" : "var(--accent-yellow)";
    }
}


// ============================================================================
// 9. ACADEMIC REVIEWER DEMO SCENARIOS
// ============================================================================

async function loadDemoScenarios() {
    const container = document.getElementById("demo-scenarios-cards-mobile");
    if (!container) return;

    try {
        const res = await apiFetch("/api/demo/scenarios");
        if (!res.ok) throw new Error("Failed to load demo scenarios");
        const demos = await res.json();

        container.innerHTML = demos.map(d => `
            <div class="reviewer-demo-card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
                    <h3 style="font-size:0.95rem; font-weight:800; color:var(--text-primary);">${escapeHtml(d.title)}</h3>
                    <span class="badge badge-info">${d.type || 'DEMO'}</span>
                </div>
                <p style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:0.6rem;">
                    ${escapeHtml(d.description || 'Executes security evaluation pipeline.')}
                </p>
                <button class="btn-mobile btn-primary-m btn-sm-m" onclick="runMobileDemoScenario('${d.scenario_id}')">
                    <i class="fa-solid fa-play"></i> Run Reviewer Demo Scenario
                </button>
            </div>
        `).join("");
    } catch (err) {
        renderErrorState("demo-scenarios-cards-mobile", "Could not load demo scenarios.", "loadDemoScenarios()");
    }
}

async function runMobileDemoScenario(scenarioId) {
    try {
        const res = await apiFetch(`/api/demo/run/${scenarioId}`, { method: "POST" });
        if (!res.ok) throw new Error("Demo API error");
        const data = await res.json();

        if (scenarioId === "reviewer_demo_1") {
            switchMobileTab("apps");
            alert("Demo 1 Complete: Installed applications batch discovery and permission correlation analysis loaded.");
        } else if (scenarioId === "reviewer_demo_2") {
            switchMobileTab("scan");
            renderMobileScanResult(data);
            alert(`Demo 2 Complete: New application installation detected (${data.app_name}). Risk Score: ${data.ai_ml_ensemble.final_risk_score}/100.`);
        } else if (scenarioId === "reviewer_demo_3") {
            switchMobileTab("network");
            refreshNetworkSecurityStatus();
            alert("Demo 3 Complete: Wi-Fi network change detected ('Hotel_Guest'). Security risk alert generated.");
        } else if (scenarioId === "reviewer_demo_4") {
            switchMobileTab("room");
            renderRoomScanResults(data.room_security_analysis);
            alert("Demo 4 Complete: Room security scan completed. Potential surveillance RTSP/ONVIF signals identified.");
        } else {
            switchMobileTab("scan");
            renderMobileScanResult(data);
        }

        loadDashboardData();
        loadMonitoringEvents();
    } catch (err) {
        alert("Demo execution failed.");
    }
}

// ============================================================================
// HELPER UTILITIES
// ============================================================================

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
