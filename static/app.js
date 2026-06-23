/* -------------------------------------------------------------
 * CyberGuard AI - Client JS Logic (SPA Routing & API Integration)
 * ------------------------------------------------------------- */

document.addEventListener("DOMContentLoaded", () => {
    
    // --- Global Application State ---
    let globalHistory = [];
    const API_BASE = window.location.origin;
    
    // --- Routing and Navigation Configuration ---
    const routes = {
        "#dashboard": { title: "Security Dashboard", subtitle: "System overview, active metrics, and quick security tips." },
        "#url-scanner": { title: "URL Safety Checker", subtitle: "Audit web links for malicious indicators and phishing targets." },
        "#phishing-detector": { title: "Phishing Detector", subtitle: "Inspect email texts for social engineering and urgent cues." },
        "#tips-generator": { title: "Security Guidelines", subtitle: "Generate AI-powered checklists for password and server hygiene." },
        "#history": { title: "Scan Log Ledger", subtitle: "Audit historical checks and export records locally." }
    };

    function navigate() {
        const hash = window.location.hash || "#dashboard";
        
        // Hide all views
        document.querySelectorAll(".subview").forEach(view => {
            view.classList.remove("active");
        });
        
        // Remove active class from menu items
        document.querySelectorAll(".menu-item").forEach(item => {
            item.classList.remove("active");
        });
        
        // Identify active view
        const targetViewId = `view-${hash.substring(1)}`;
        const targetView = document.getElementById(targetViewId);
        
        if (targetView) {
            targetView.classList.add("active");
            
            // Set header metadata
            const meta = routes[hash] || routes["#dashboard"];
            document.getElementById("page-title").textContent = meta.title;
            document.getElementById("page-subtitle").textContent = meta.subtitle;
            
            // Activate sidebar button
            const menuBtn = document.getElementById(`menu-${hash.substring(1)}`);
            if (menuBtn) menuBtn.classList.add("active");
            
            // Run view-specific loaders
            if (hash === "#dashboard") {
                loadStats();
                loadRecentScans();
            } else if (hash === "#history") {
                loadFullHistory();
            }
        }
    }

    window.addEventListener("hashchange", navigate);
    // Initial load
    navigate();


    // --- Status and Connection Checker ---
    async function checkSystemStatus() {
        const statusDesc = document.getElementById("api-status");
        const keyBadge = document.getElementById("key-badge");
        const keyBadgeText = document.getElementById("key-badge-text");
        
        try {
            const res = await fetch(`${API_BASE}/api/stats`);
            if (res.ok) {
                statusDesc.textContent = "Gemini Connected";
                keyBadge.classList.remove("missing");
                keyBadgeText.textContent = "API Key Active";
            } else {
                const data = await res.json();
                statusDesc.textContent = "API Key Required";
                keyBadge.classList.add("missing");
                keyBadgeText.textContent = "Key Missing / Inactive";
            }
        } catch (err) {
            statusDesc.textContent = "Offline / Connection Lost";
            keyBadge.classList.add("missing");
            keyBadgeText.textContent = "Server Offline";
        }
    }
    
    // Check status immediately and repeat every 30 seconds
    checkSystemStatus();
    setInterval(checkSystemStatus, 30000);


    // --- Gauge Chart Visualizer ---
    function createGaugeHTML(score, verdict) {
        const circumference = 251.2;
        let numericScore = parseFloat(score);
        let offset = circumference;
        let color = "var(--text-muted)";
        let glow = "none";
        let textScore = "N/A";
        let textVerdict = verdict ? verdict.toUpperCase() : "INFO";
        
        if (!isNaN(numericScore)) {
            offset = circumference * (1 - numericScore / 10);
            textScore = numericScore.toFixed(0);
            if (numericScore <= 3) {
                color = "var(--color-safe)";
                glow = "var(--color-safe-glow)";
            } else if (numericScore <= 7) {
                color = "var(--color-warning)";
                glow = "var(--color-warning-glow)";
            } else {
                color = "var(--color-danger)";
                glow = "var(--color-danger-glow)";
            }
            
            // Adjust coloring for specific verdict matches
            if (verdict === "Phishing" || verdict === "Malicious") {
                color = "var(--color-danger)";
                glow = "var(--color-danger-glow)";
            }
        }
        
        return `
        <svg viewBox="0 0 100 100" class="gauge-svg">
            <circle cx="50" cy="50" r="40" class="gauge-track"></circle>
            <circle cx="50" cy="50" r="40" class="gauge-fill" 
                style="stroke-dasharray: 251.2; stroke-dashoffset: ${offset}; stroke: ${color}; filter: drop-shadow(0 0 6px ${glow});">
            </circle>
            <text x="50" y="49" class="gauge-val" style="fill: var(--text-primary); font-size: 18px; font-weight: 700; text-anchor: middle; transform: rotate(90deg); transform-origin: center;">${textScore}</text>
            <text x="50" y="65" class="gauge-label" style="fill: var(--text-secondary); font-size: 8px; font-weight: 600; text-anchor: middle; transform: rotate(90deg); transform-origin: center; letter-spacing: 0.05em;">${textVerdict}</text>
        </svg>
        `;
    }

    function animateDashboardGauge(score, verdict) {
        const fill = document.getElementById("dash-gauge-fill");
        const val = document.getElementById("dash-gauge-val");
        const lbl = document.getElementById("dash-gauge-lbl");
        
        const circumference = 251.2;
        let numericScore = parseFloat(score);
        
        if (isNaN(numericScore) || numericScore === 0) {
            fill.style.strokeDashoffset = circumference;
            val.textContent = "0.0";
            lbl.textContent = "SAFE";
            fill.style.stroke = "var(--color-safe)";
            return;
        }
        
        const offset = circumference * (1 - numericScore / 10);
        fill.style.strokeDashoffset = offset;
        val.textContent = numericScore.toFixed(1);
        lbl.textContent = verdict ? verdict.toUpperCase() : (numericScore <= 3 ? "SAFE" : (numericScore <= 7 ? "SUSPICIOUS" : "THREAT"));
        
        if (numericScore <= 3) {
            fill.style.stroke = "var(--color-safe)";
            fill.style.filter = "drop-shadow(0 0 8px var(--color-safe-glow))";
        } else if (numericScore <= 7) {
            fill.style.stroke = "var(--color-warning)";
            fill.style.filter = "drop-shadow(0 0 8px var(--color-warning-glow))";
        } else {
            fill.style.stroke = "var(--color-danger)";
            fill.style.filter = "drop-shadow(0 0 8px var(--color-danger-glow))";
        }
    }


    // --- Dashboard Stats and Briefings ---
    async function loadStats() {
        try {
            const res = await fetch(`${API_BASE}/api/stats`);
            if (!res.ok) return;
            const data = await res.json();
            
            // Update stats cards
            document.getElementById("stat-total-scans").textContent = data.total_scans;
            document.getElementById("stat-safe-scans").textContent = data.safe_count;
            document.getElementById("stat-threats").textContent = data.threat_count;
            document.getElementById("stat-avg-risk").textContent = data.average_risk.toFixed(1);
            
            // Calculate safety rate percentage
            const safePct = data.total_scans > 0 ? Math.round((data.safe_count / data.total_scans) * 100) : 0;
            document.getElementById("stat-safe-pct").textContent = `${safePct}% of total scans`;
            
            // Update chart dashboard gauges
            animateDashboardGauge(data.average_risk, data.average_risk <= 3 ? "SAFE" : (data.average_risk <= 7 ? "SUSPICIOUS" : "THREAT"));
            
            // Update breakdown numbers
            document.getElementById("dash-low-risk-count").textContent = data.safe_count;
            document.getElementById("dash-med-risk-count").textContent = data.suspicious_count;
            document.getElementById("dash-high-risk-count").textContent = data.threat_count;
            
        } catch (err) {
            console.error("Failed to load statistics: ", err);
        }
    }

    // Refresh general tips briefs
    async function loadDailyTip(topic = "") {
        const briefBox = document.getElementById("dash-tip-card");
        briefBox.innerHTML = `<div class="tip-loading"><i class="fa-solid fa-circle-notch fa-spin"></i> Fetching AI briefing...</div>`;
        
        try {
            const res = await fetch(`${API_BASE}/api/scan/tip`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ topic: topic })
            });
            
            if (res.ok) {
                const data = await res.json();
                briefBox.innerHTML = `
                    <div class="tip-headline">${data.headline}</div>
                    <div class="tip-text">${data.explanation}</div>
                `;
            } else {
                briefBox.innerHTML = `<div class="text-muted"><i class="fa-solid fa-triangle-exclamation"></i> Configure your GEMINI_API_KEY to retrieve security briefings.</div>`;
            }
        } catch (err) {
            briefBox.innerHTML = `<div class="text-muted"><i class="fa-solid fa-triangle-exclamation"></i> Error loading briefs: ${err.message}</div>`;
        }
    }
    
    // Initial daily tip loading
    loadDailyTip();
    
    document.getElementById("btn-refresh-tip").addEventListener("click", () => {
        const topicsList = ["passwords", "MFA", "email phishing", "public Wi-Fi", "ransomware", "social engineering"];
        const randTopic = topicsList[Math.floor(Math.random() * topicsList.length)];
        loadDailyTip(randTopic);
    });


    // --- Load Log Lists (Recent Scans & Full History) ---
    
    function createRowHTML(scan, index) {
        let vClass = "badge-success";
        if (scan.verdict === "Suspicious") vClass = "badge-warning";
        else if (scan.verdict === "Malicious" || scan.verdict === "Phishing") vClass = "badge-danger";
        
        let scoreClass = "";
        let numericScore = parseFloat(scan.risk_score);
        if (!isNaN(numericScore)) {
            if (numericScore <= 3) scoreClass = "green-text";
            else if (numericScore <= 7) scoreClass = "yellow-text";
            else scoreClass = "red-text";
        }
        
        // Truncate target input if too long
        let displayInput = scan.input;
        if (displayInput.length > 50) {
            displayInput = displayInput.substring(0, 47) + "...";
        }

        return `
        <tr>
            <td>${scan.timestamp}</td>
            <td><span class="badge badge-accent">${scan.scan_type}</span></td>
            <td title="${scan.input}">${displayInput}</td>
            <td><strong class="${scoreClass}">${scan.risk_score}</strong></td>
            <td><span class="badge ${vClass}">${scan.verdict}</span></td>
            <td>
                <button class="btn btn-secondary btn-sm btn-details" data-idx="${index}">
                    <i class="fa-solid fa-circle-info"></i> Details
                </button>
            </td>
        </tr>
        `;
    }

    async function loadRecentScans() {
        const tableBody = document.querySelector("#recent-scans-table tbody");
        try {
            const res = await fetch(`${API_BASE}/api/history`);
            if (!res.ok) return;
            const data = await res.json();
            globalHistory = data;
            
            if (data.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No recent activities. Run a scanner to begin.</td></tr>`;
                return;
            }
            
            // Limit to last 5 entries on the dashboard
            const recent = data.slice(0, 5);
            tableBody.innerHTML = recent.map((scan, idx) => createRowHTML(scan, idx)).join("");
            
            // Bind details button
            tableBody.querySelectorAll(".btn-details").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    const idx = e.currentTarget.getAttribute("data-idx");
                    openDetailsModal(globalHistory[idx]);
                });
            });
            
        } catch (err) {
            console.error("Failed to load recent activities: ", err);
        }
    }

    async function loadFullHistory() {
        const tableBody = document.querySelector("#history-table tbody");
        const countText = document.getElementById("history-count-text");
        
        try {
            const res = await fetch(`${API_BASE}/api/history`);
            if (!res.ok) return;
            const data = await res.json();
            globalHistory = data;
            
            countText.textContent = `Showing ${data.length} scan entries`;
            
            if (data.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No scans saved in history logs.</td></tr>`;
                return;
            }
            
            tableBody.innerHTML = data.map((scan, idx) => createRowHTML(scan, idx)).join("");
            
            // Bind details button
            tableBody.querySelectorAll(".btn-details").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    const idx = e.currentTarget.getAttribute("data-idx");
                    openDetailsModal(globalHistory[idx]);
                });
            });
            
        } catch (err) {
            console.error("Failed to load logs: ", err);
        }
    }


    // --- Details Modal Display ---
    const modal = document.getElementById("details-modal");
    
    function openDetailsModal(scan) {
        document.getElementById("modal-meta-date").textContent = scan.timestamp;
        document.getElementById("modal-meta-type").textContent = scan.scan_type;
        document.getElementById("modal-meta-score").textContent = `${scan.risk_score}/10`;
        
        const verdictBadge = document.getElementById("modal-meta-verdict");
        verdictBadge.textContent = scan.verdict;
        verdictBadge.className = "val badge"; // Reset classes
        
        if (scan.verdict === "Safe" || scan.verdict === "N/A") verdictBadge.classList.add("badge-success");
        else if (scan.verdict === "Suspicious") verdictBadge.classList.add("badge-warning");
        else verdictBadge.classList.add("badge-danger");
        
        document.getElementById("modal-scanned-target").textContent = scan.input;
        document.getElementById("modal-analysis-text").textContent = scan.analysis;
        
        modal.classList.remove("hidden");
    }

    function closeModal() {
        modal.classList.add("hidden");
    }

    document.getElementById("modal-close-btn").addEventListener("click", closeModal);
    document.getElementById("modal-ok-btn").addEventListener("click", closeModal);
    modal.addEventListener("click", (e) => {
        if (e.target === modal) closeModal();
    });


    // --- Form Scanning Handling: URL Scanner ---
    const urlForm = document.getElementById("url-scan-form");
    const urlLoader = document.getElementById("url-loader");
    const urlResults = document.getElementById("url-results");
    
    urlForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const urlInput = document.getElementById("scan-url-input").value.trim();
        
        urlResults.classList.add("hidden");
        urlLoader.classList.remove("hidden");
        
        try {
            const res = await fetch(`${API_BASE}/api/scan/url`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: urlInput })
            });
            
            urlLoader.classList.add("hidden");
            
            if (res.ok) {
                const data = await res.json();
                
                // Set verdict banner
                const banner = document.getElementById("url-verdict-banner");
                const title = document.getElementById("url-verdict-title");
                
                title.textContent = `VERDICT: ${data.verdict.toUpperCase()}`;
                banner.className = "result-header-bar"; // reset
                
                if (data.verdict === "Safe") banner.classList.add("verdict-green");
                else if (data.verdict === "Suspicious") banner.classList.add("verdict-yellow");
                else banner.classList.add("verdict-red");
                
                // Render custom SVG gauge
                const gaugeContainer = document.getElementById("url-gauge-container");
                gaugeContainer.innerHTML = createGaugeHTML(data.risk_score, data.verdict);
                
                // Render analysis texts
                document.getElementById("url-reasoning-text").textContent = data.reasoning;
                
                // Recommendations list
                const recList = document.getElementById("url-recommendations-list");
                recList.innerHTML = data.recommendations.map(rec => `<li>${rec}</li>`).join("");
                
                urlResults.classList.remove("hidden");
            } else {
                const errData = await res.json();
                alert(`URL Analysis Error: ${errData.detail}`);
            }
        } catch (err) {
            urlLoader.classList.add("hidden");
            alert(`Network error occurred: ${err.message}`);
        }
    });


    // --- Form Scanning Handling: Phishing Detector ---
    const emailForm = document.getElementById("email-scan-form");
    const emailLoader = document.getElementById("email-loader");
    const emailResults = document.getElementById("email-results");
    
    emailForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const emailInput = document.getElementById("scan-email-input").value.trim();
        
        emailResults.classList.add("hidden");
        emailLoader.classList.remove("hidden");
        
        try {
            const res = await fetch(`${API_BASE}/api/scan/email`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ content: emailInput })
            });
            
            emailLoader.classList.add("hidden");
            
            if (res.ok) {
                const data = await res.json();
                
                // Verdict Banner
                const banner = document.getElementById("email-verdict-banner");
                const title = document.getElementById("email-verdict-title");
                
                title.textContent = `VERDICT: ${data.verdict.toUpperCase()}`;
                banner.className = "result-header-bar";
                
                if (data.verdict === "Safe") banner.classList.add("verdict-green");
                else if (data.verdict === "Suspicious") banner.classList.add("verdict-yellow");
                else banner.classList.add("verdict-purple");
                
                // Score Gauge
                const gaugeContainer = document.getElementById("email-gauge-container");
                gaugeContainer.innerHTML = createGaugeHTML(data.risk_score, data.verdict);
                
                // Indicators Badges
                const badgeBox = document.getElementById("email-indicators-badges");
                if (data.phishing_indicators && data.phishing_indicators.length > 0) {
                    badgeBox.innerHTML = data.phishing_indicators.map(ind => `<span class="badge badge-danger"><i class="fa-solid fa-triangle-exclamation"></i> ${ind}</span>`).join("");
                } else {
                    badgeBox.innerHTML = `<span class="badge badge-success"><i class="fa-solid fa-circle-check"></i> No Threat Headers Detected</span>`;
                }
                
                // Reasoning & Recs
                document.getElementById("email-reasoning-text").textContent = data.reasoning;
                const recList = document.getElementById("email-recommendations-list");
                recList.innerHTML = data.recommendations.map(rec => `<li>${rec}</li>`).join("");
                
                emailResults.classList.remove("hidden");
            } else {
                const errData = await res.json();
                alert(`Email Analysis Error: ${errData.detail}`);
            }
        } catch (err) {
            emailLoader.classList.add("hidden");
            alert(`Network error occurred: ${err.message}`);
        }
    });


    // --- Form Scanning Handling: Security Tips Generator ---
    const tipForm = document.getElementById("tip-gen-form");
    const tipLoader = document.getElementById("tip-loader");
    const tipResults = document.getElementById("tip-results");
    
    async function requestTips(topicText) {
        tipResults.classList.add("hidden");
        tipLoader.classList.remove("hidden");
        
        try {
            const res = await fetch(`${API_BASE}/api/scan/tip`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ topic: topicText })
            });
            
            tipLoader.classList.add("hidden");
            
            if (res.ok) {
                const data = await res.json();
                
                document.getElementById("tip-result-topic").textContent = data.topic;
                document.getElementById("tip-result-headline").textContent = data.headline;
                document.getElementById("tip-result-explanation").textContent = data.explanation;
                
                const actionBox = document.getElementById("tip-result-actions");
                actionBox.innerHTML = data.action_items.map(act => `<li>${act}</li>`).join("");
                
                tipResults.classList.remove("hidden");
            } else {
                const errData = await res.json();
                alert(`Tip Generation Error: ${errData.detail}`);
            }
        } catch (err) {
            tipLoader.classList.add("hidden");
            alert(`Network error occurred: ${err.message}`);
        }
    }
    
    tipForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const topic = document.getElementById("tip-topic-input").value.trim();
        requestTips(topic);
    });
    
    // Quick selectors click
    document.querySelectorAll(".topic-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const topic = e.currentTarget.getAttribute("data-topic");
            document.getElementById("tip-topic-input").value = topic;
            requestTips(topic);
        });
    });


    // --- History Filtering and CSV Download ---
    
    // Filtering history items
    const searchInput = document.getElementById("search-history-input");
    searchInput.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase().trim();
        const rows = document.querySelectorAll("#history-table tbody tr");
        
        let visibleCount = 0;
        rows.forEach(row => {
            const cells = Array.from(row.querySelectorAll("td"));
            const textMatch = cells.some(cell => cell.textContent.toLowerCase().includes(query));
            if (textMatch) {
                row.style.display = "";
                visibleCount++;
            } else {
                row.style.display = "none";
            }
        });
        
        document.getElementById("history-count-text").textContent = `Showing ${visibleCount} of ${globalHistory.length} scan entries`;
    });

    // CSV Download trigger
    document.getElementById("btn-export-csv").addEventListener("click", () => {
        if (globalHistory.length === 0) {
            alert("No logs available in history to export.");
            return;
        }
        
        // Build CSV content
        const headers = ["Timestamp", "Scan Type", "Input/Target", "Risk Score", "Verdict", "Summary Analysis"];
        const csvRows = [headers.join(",")];
        
        globalHistory.forEach(scan => {
            // Escape double quotes in strings for proper CSV format
            const cleanTarget = `"${scan.input.replace(/"/g, '""')}"`;
            const cleanAnalysis = `"${scan.analysis.replace(/"/g, '""')}"`;
            const row = [
                scan.timestamp,
                scan.scan_type,
                cleanTarget,
                scan.risk_score,
                scan.verdict,
                cleanAnalysis
            ];
            csvRows.push(row.join(","));
        });
        
        const csvBlob = new Blob([csvRows.join("\n")], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(csvBlob);
        
        const link = document.createElement("a");
        link.setAttribute("href", url);
        link.setAttribute("download", `cyberguard_scan_history_${new Date().toISOString().slice(0,10)}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });

});
