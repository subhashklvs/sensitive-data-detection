/* -------------------------------------------------------------
   ShieldAudit AI - Frontend Application Logic (JS)
------------------------------------------------------------- */

document.addEventListener("DOMContentLoaded", () => {
    // --- Application State ---
    const state = {
        token: localStorage.getItem("shieldaudit_token") || "",
        user: JSON.parse(localStorage.getItem("shieldaudit_user") || "null"),
        currentDoc: null,
        chatHistory: [],
        findingsChart: null
    };

    // --- DOM Elements ---
    const navItems = document.querySelectorAll(".nav-item");
    const tabContents = document.querySelectorAll(".tab-content");
    const pageTitle = document.getElementById("page-title");
    const pageSubtitle = document.getElementById("page-subtitle");
    
    // Auth Elements
    const authContainer = document.getElementById("auth-container");
    const loginForm = document.getElementById("login-form");
    const registerForm = document.getElementById("register-form");
    const switchToRegister = document.getElementById("switch-to-register");
    const switchToLogin = document.getElementById("switch-to-login");
    const headerUsername = document.getElementById("header-username");
    
    // Profile Elements
    const profileId = document.getElementById("profile-id");
    const profileDisplayUsername = document.getElementById("profile-display-username");
    const profileDisplayEmail = document.getElementById("profile-display-email");
    const profileJoined = document.getElementById("profile-joined");
    const profileAvatarLetter = document.getElementById("profile-avatar-letter");
    const btnLogout = document.getElementById("btn-logout");
    
    // Upload Elements
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("file-input");
    const uploadLoading = document.getElementById("upload-loading");
    const uploadProgress = document.getElementById("upload-progress");
    const resultsContainer = document.getElementById("results-container");
    
    // Sidebar locked tabs
    const navChatBtn = document.getElementById("nav-chat-btn");
    const navMaskerBtn = document.getElementById("nav-masker-btn");
    
    // Metadata & Risk Elements
    const metaFilename = document.getElementById("meta-filename");
    const metaFiletype = document.getElementById("meta-filetype");
    const metaDetections = document.getElementById("meta-detections");
    const metaRating = document.getElementById("meta-rating");
    
    const riskScoreCircle = document.getElementById("risk-score-circle");
    const riskScoreValue = document.getElementById("risk-score-value");
    const riskLevelBadge = document.getElementById("risk-level-badge");
    const riskCardElement = document.getElementById("risk-card-element");
    
    const metricsGrid = document.getElementById("metrics-grid");
    const findingsTableBody = document.getElementById("findings-table-body");
    
    // Sub-tabs in Details panel
    const detailsTabBtns = document.querySelectorAll(".details-tab-btn");
    const detailsTabContents = document.querySelectorAll(".details-tab-content");
    
    const observationsList = document.getElementById("compliance-observations-list");
    const risksList = document.getElementById("compliance-risks-list");
    const remediationList = document.getElementById("compliance-remediation-list");
    
    // Chat Elements
    const chatMessages = document.getElementById("chat-messages");
    const chatInput = document.getElementById("chat-input");
    const chatSendBtn = document.getElementById("chat-send-btn");
    const suggestionBtns = document.querySelectorAll(".suggestion-btn");
    
    // Masker Elements
    const originalTextPreview = document.getElementById("original-text-preview");
    const redactedTextPreview = document.getElementById("redacted-text-preview");
    const btnCopyOriginal = document.getElementById("btn-copy-original");
    const btnCopyRedacted = document.getElementById("btn-copy-redacted");
    const btnDownloadRedacted = document.getElementById("btn-download-redacted");
    const downloadDropdown = document.getElementById("download-dropdown");
    const downloadPdfBtn = document.getElementById("download-pdf");
    const downloadTxtBtn = document.getElementById("download-txt");
    const downloadCsvBtn = document.getElementById("download-csv");
    
    // Audit Elements
    const auditTableBody = document.getElementById("audit-table-body");
    const btnRefreshLogs = document.getElementById("btn-refresh-logs");


    // --- 1. Tab Navigation & Routing ---
    const tabDetails = {
        dashboard: { title: "Compliance Dashboard", subtitle: "Upload documents to scan for PII, financial risk, and compliance exposure." },
        chat: { title: "Interactive Security Assistant", subtitle: "Ask questions, verify details, and check specific requirements on your document." },
        masker: { title: "Sensitive Document Masker", subtitle: "Inspect original document content and download the cleaned/redacted version." },
        audit: { title: "Security Audit Logs", subtitle: "Review compliance history and activity logs. Private data is never stored." },
        profile: { title: "User Profile", subtitle: "Account information for the active ShieldAudit AI session." }
    };

    function switchTab(tabId) {
        // Disable lock checks for permitted transitions
        const btn = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
        if (btn && btn.disabled) return;

        navItems.forEach(item => item.classList.remove("active"));
        tabContents.forEach(tab => tab.classList.remove("active"));

        const activeNav = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
        const activeTab = document.getElementById(`tab-${tabId}`);
        
        if (activeNav) activeNav.classList.add("active");
        if (activeTab) activeTab.classList.add("active");

        // Update titles
        if (tabDetails[tabId]) {
            pageTitle.textContent = tabDetails[tabId].title;
            pageSubtitle.textContent = tabDetails[tabId].subtitle;
        }

        // Lazy load logs
        if (tabId === "audit") {
            loadAuditLogs();
        }
    }

    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const tabId = item.getAttribute("data-tab");
            switchTab(tabId);
        });
    });

    // Sub-tabs (Dashboard details)
    detailsTabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            detailsTabBtns.forEach(b => b.classList.remove("active"));
            detailsTabContents.forEach(c => c.classList.remove("active"));
            
            btn.classList.add("active");
            const subtabId = btn.getAttribute("data-subtab");
            document.getElementById("subtab-" + subtabId).classList.add("active");
        });
    });


    // --- 2. Authentication State Management ---
    function checkAuth() {
        if (state.token && state.user) {
            authContainer.style.display = "none";
            document.querySelector(".app-container").style.display = "flex";
            
            // Update user details
            headerUsername.textContent = state.user.username;
            profileId.textContent = state.user.id;
            profileDisplayUsername.textContent = state.user.username;
            profileDisplayEmail.textContent = state.user.email;
            profileAvatarLetter.textContent = state.user.username.charAt(0).toUpperCase();
            
            if (state.user.created_at) {
                const date = new Date(state.user.created_at);
                profileJoined.textContent = date.toLocaleDateString() + " " + date.toLocaleTimeString();
            } else {
                profileJoined.textContent = "-";
            }
        } else {
            authContainer.style.display = "flex";
            document.querySelector(".app-container").style.display = "none";
        }
    }

    // Toggle forms
    switchToRegister.addEventListener("click", () => {
        loginForm.style.display = "none";
        registerForm.style.display = "block";
        document.getElementById("auth-subtitle").textContent = "Create an account to start scanning files.";
    });

    switchToLogin.addEventListener("click", () => {
        registerForm.style.display = "none";
        loginForm.style.display = "block";
        document.getElementById("auth-subtitle").textContent = "Sign in to scan and audit sensitive files.";
    });

    // Login Submission
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const usernameVal = document.getElementById("login-username").value.trim();
        const passwordVal = document.getElementById("login-password").value;
        
        try {
            const res = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: usernameVal, password: passwordVal })
            });
            
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || "Login failed.");
            }
            
            const data = await res.json();
            state.token = data.token;
            state.user = data.user;
            localStorage.setItem("shieldaudit_token", data.token);
            localStorage.setItem("shieldaudit_user", JSON.stringify(data.user));
            
            loginForm.reset();
            checkAuth();
            switchTab("dashboard");
        } catch (err) {
            alert("Error: " + err.message);
        }
    });

    // Register Submission
    registerForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const usernameVal = document.getElementById("register-username").value.trim();
        const emailVal = document.getElementById("register-email").value.trim();
        const passwordVal = document.getElementById("register-password").value;
        
        try {
            const res = await fetch("/api/auth/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: usernameVal, email: emailVal, password: passwordVal })
            });
            
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || "Registration failed.");
            }
            
            const data = await res.json();
            state.token = data.token;
            state.user = data.user;
            localStorage.setItem("shieldaudit_token", data.token);
            localStorage.setItem("shieldaudit_user", JSON.stringify(data.user));
            
            registerForm.reset();
            checkAuth();
            switchTab("dashboard");
        } catch (err) {
            alert("Error: " + err.message);
        }
    });

    // Logout
    btnLogout.addEventListener("click", () => {
        state.token = "";
        state.user = null;
        localStorage.removeItem("shieldaudit_token");
        localStorage.removeItem("shieldaudit_user");
        checkAuth();
    });


    // --- 3. Document Drag and Drop Upload ---
    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropZone.classList.add("dragover");
        }, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropZone.classList.remove("dragover");
        }, false);
    });

    dropZone.addEventListener("drop", (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length) {
            handleFileUpload(files[0]);
        }
    });

    dropZone.addEventListener("click", () => {
        fileInput.click();
    });

    fileInput.addEventListener("change", (e) => {
        if (fileInput.files.length) {
            handleFileUpload(fileInput.files[0]);
        }
    });

    async function handleFileUpload(file) {
        const ext = file.name.split(".").pop().toLowerCase();
        if (!["pdf", "txt", "csv"].includes(ext)) {
            alert("Unsupported format. Please upload PDF, TXT, or CSV files.");
            return;
        }

        // Show loading state
        dropZone.style.display = "none";
        uploadLoading.style.display = "flex";
        resultsContainer.style.display = "none";
        
        // Disable locked navigation tabs
        navChatBtn.disabled = true;
        navChatBtn.querySelector(".lock-icon").style.display = "inline";
        navMaskerBtn.disabled = true;
        navMaskerBtn.querySelector(".lock-icon").style.display = "inline";

        uploadProgress.style.width = "10%";

        const formData = new FormData();
        formData.append("file", file);

        setTimeout(() => { uploadProgress.style.width = "40%"; }, 800);

        try {
            const response = await fetch("/api/upload", {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${state.token}`
                },
                body: formData
            });

            uploadProgress.style.width = "85%";

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.detail || "Error processing file.");
            }

            const data = await response.json();
            uploadProgress.style.width = "100%";

            setTimeout(() => {
                state.currentDoc = data;
                renderDashboardResults(data);
                
                // Unlock tabs
                navChatBtn.disabled = false;
                navChatBtn.querySelector(".lock-icon").style.display = "none";
                navMaskerBtn.disabled = false;
                navMaskerBtn.querySelector(".lock-icon").style.display = "none";

                // Setup chat welcome
                initializeChat();
                
                // Hide loading, show results
                uploadLoading.style.display = "none";
                dropZone.style.display = "flex";
                resultsContainer.style.display = "block";
            }, 500);

        } catch (error) {
            loggerError(error);
            alert(`Analysis failed: ${error.message}`);
            uploadLoading.style.display = "none";
            dropZone.style.display = "flex";
        }
    }


    // --- 4. Render Dashboard Analysis Results ---
    function renderDashboardResults(data) {
        // Show/hide CSV download option based on document type
        if (data.file_type.toLowerCase() === ".csv") {
            downloadCsvBtn.style.display = "flex";
        } else {
            downloadCsvBtn.style.display = "none";
        }

        // Metadata
        metaFilename.textContent = data.file_name;
        metaFiletype.textContent = data.file_type.toUpperCase().substring(1);
        metaDetections.textContent = data.findings.length;
        metaRating.textContent = data.compliance_report.risk_level;

        // Risk Card Animation
        const score = data.compliance_report.risk_score;
        const level = data.compliance_report.risk_level;
        
        let riskColor = "var(--color-low)";
        let shadowColor = "var(--color-low-glow)";
        
        if (level === "Medium") {
            riskColor = "var(--color-medium)";
            shadowColor = "var(--color-medium-glow)";
        } else if (level === "High") {
            riskColor = "var(--color-high)";
            shadowColor = "var(--color-high-glow)";
        }

        riskLevelBadge.textContent = `${level} Risk`;
        riskLevelBadge.style.backgroundColor = riskColor;
        riskLevelBadge.style.boxShadow = `0 4px 15px ${shadowColor}`;
        riskScoreCircle.style.stroke = riskColor;
        riskScoreCircle.style.filter = `drop-shadow(0 0 6px ${riskColor})`;
        
        // Animate circular meter
        const dashOffset = 251 - (251 * score / 100);
        riskScoreCircle.style.strokeDashoffset = dashOffset;
        
        // Counter animation
        let count = 0;
        const interval = setInterval(() => {
            if (count >= score) {
                riskScoreValue.textContent = score;
                clearInterval(interval);
            } else {
                count++;
                riskScoreValue.textContent = count;
            }
        }, 12);

        // Metrics Grid
        const typeCounts = {};
        data.findings.forEach(f => {
            typeCounts[f.type] = (typeCounts[f.type] || 0) + 1;
        });

        metricsGrid.innerHTML = "";
        if (Object.keys(typeCounts).length === 0) {
            metricsGrid.innerHTML = `<div class="glass-panel" style="grid-column: 1/-1; padding: 16px; text-align: center; color: var(--text-muted);">No sensitive metrics detected.</div>`;
        } else {
            Object.entries(typeCounts).forEach(([type, count]) => {
                const card = document.createElement("div");
                card.className = "metric-card";
                card.innerHTML = `
                    <h4>${count}</h4>
                    <p>${type}</p>
                `;
                metricsGrid.appendChild(card);
            });
        }

        // Findings Table
        findingsTableBody.innerHTML = "";
        if (data.findings.length === 0) {
            findingsTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Clean scan! No sensitive strings were detected.</td></tr>`;
        } else {
            data.findings.forEach(f => {
                const tr = document.createElement("tr");
                const sourceBadge = f.source.includes("AI") ? "badge-ai" : "badge-regex";
                const confBadge = f.confidence === "High" ? "badge-low" : (f.confidence === "Medium" ? "badge-med" : "badge-high");
                
                tr.innerHTML = `
                    <td><strong>${f.type}</strong></td>
                    <td class="text-yellow"><code>${escapeHTML(f.value)}</code></td>
                    <td style="font-size: 12px; color: var(--text-secondary); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHTML(f.context)}">${escapeHTML(f.context)}</td>
                    <td><span class="badge ${sourceBadge}">${f.source.includes("AI") ? "AI LLM" : "Rules Pattern"}</span></td>
                    <td><span class="badge ${confBadge}">${f.confidence}</span></td>
                `;
                findingsTableBody.appendChild(tr);
            });
        }

        // Compliance lists
        observationsList.innerHTML = "";
        data.compliance_report.observations.forEach(o => {
            const li = document.createElement("li");
            li.textContent = o;
            observationsList.appendChild(li);
        });

        risksList.innerHTML = "";
        data.compliance_report.risks.forEach(r => {
            const li = document.createElement("li");
            li.textContent = r;
            risksList.appendChild(li);
        });

        remediationList.innerHTML = "";
        data.compliance_report.remediation.forEach(rem => {
            const li = document.createElement("li");
            li.textContent = rem;
            remediationList.appendChild(li);
        });

        // Document Masker content
        originalTextPreview.textContent = data.text;
        redactedTextPreview.textContent = data.redacted_text;

        // Render chart
        renderChart(typeCounts);
    }

    // Chart.js render helper
    function renderChart(typeCounts) {
        if (state.findingsChart) {
            state.findingsChart.destroy();
        }

        const ctx = document.getElementById("findings-chart").getContext("2d");
        const labels = Object.keys(typeCounts);
        const values = Object.values(typeCounts);

        if (labels.length === 0) {
            // Empty state placeholder
            return;
        }

        state.findingsChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: [
                        "#6366f1", "#06b6d4", "#ec4899", "#f59e0b", "#10b981",
                        "#8b5cf6", "#f97316", "#3b82f6", "#ef4444"
                    ],
                    borderWidth: 1,
                    borderColor: "rgba(255,255,255,0.06)"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: "right",
                        labels: {
                            color: "#94a3b8",
                            font: { size: 9, family: "Inter" },
                            boxWidth: 8,
                            padding: 6
                        }
                    }
                },
                cutout: "70%"
            }
        });
    }


    // --- 5. Interactive Chat Engine ---
    function initializeChat() {
        chatMessages.innerHTML = "";
        state.chatHistory = [];
        
        appendChatMessage("assistant", `
            <p>👋 Hello! I am your AI compliance companion.</p>
            <p>I have scanned <strong>${state.currentDoc.file_name}</strong>. Feel free to ask questions about the sensitive details, compliance issues, or risk level detected in this document.</p>
        `);
    }

    function appendChatMessage(role, content, isLoading = false) {
        const bubble = document.createElement("div");
        bubble.className = `chat-bubble ${role}`;
        if (isLoading) {
            bubble.id = "chat-loading-bubble";
            bubble.innerHTML = `<span class="pulse-green" style="display:inline-block; vertical-align: middle;"></span> Analyzing...`;
        } else {
            bubble.innerHTML = content;
        }
        chatMessages.appendChild(bubble);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    async function sendChatMessage(query) {
        if (!query.trim() || !state.currentDoc) return;

        appendChatMessage("user", `<p>${escapeHTML(query)}</p>`);
        chatInput.value = "";
        chatInput.style.height = "auto";
        
        // Show loading bubble
        appendChatMessage("assistant", "", true);

        try {
            const response = await fetch("/api/chat", {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${state.token}`
                },
                body: JSON.stringify({
                    document_text: state.currentDoc.text,
                    query: query,
                    chat_history: state.chatHistory
                })
            });

            // Remove loading bubble
            const loadingBubble = document.getElementById("chat-loading-bubble");
            if (loadingBubble) loadingBubble.remove();

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.detail || "Error generating message response.");
            }

            const data = await response.json();
            
            // Render markdown style response
            const renderedResponse = formatMarkdown(data.answer);
            appendChatMessage("assistant", renderedResponse);

            // Save to history
            state.chatHistory.push({ role: "user", content: query });
            state.chatHistory.push({ role: "model", content: data.answer });

            if (state.chatHistory.length > 20) {
                state.chatHistory.shift();
                state.chatHistory.shift();
            }

        } catch (error) {
            const loadingBubble = document.getElementById("chat-loading-bubble");
            if (loadingBubble) loadingBubble.remove();
            
            loggerError(error);
            appendChatMessage("assistant", `<p class="text-orange">⚠️ Error generating AI response: ${error.message}</p>`);
        }
    }

    chatSendBtn.addEventListener("click", () => {
        sendChatMessage(chatInput.value);
    });

    chatInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            sendChatMessage(chatInput.value);
        }
    });

    // Suggestion bubbles
    suggestionBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            sendChatMessage(btn.textContent);
        });
    });


    // --- 6. Document Redaction & Actions ---
    btnCopyOriginal.addEventListener("click", () => {
        if (state.currentDoc) {
            navigator.clipboard.writeText(state.currentDoc.text);
            alert("Original text copied to clipboard!");
        }
    });

    btnCopyRedacted.addEventListener("click", () => {
        if (state.currentDoc) {
            navigator.clipboard.writeText(state.currentDoc.redacted_text);
            alert("Redacted text copied to clipboard!");
        }
    });

    // Toggle download dropdown
    btnDownloadRedacted.addEventListener("click", (e) => {
        e.stopPropagation();
        downloadDropdown.classList.toggle("show");
    });

    // Close dropdown when clicking outside
    document.addEventListener("click", () => {
        downloadDropdown.classList.remove("show");
    });

    // 1. Download as PDF
    downloadPdfBtn.addEventListener("click", () => {
        if (!state.currentDoc) return;
        
        const origName = state.currentDoc.file_name;
        const nameParts = origName.split(".");
        nameParts.pop(); // remove original extension
        const baseName = nameParts.join(".");
        const newName = `redacted_${baseName}.pdf`;

        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            
            // PDF Styling and Branding
            doc.setFont("helvetica", "bold");
            doc.setFontSize(16);
            doc.setTextColor(99, 102, 241); // #6366f1 (var(--color-primary))
            doc.text("ShieldAudit AI - Sensitive Data Detection", 15, 20);
            
            doc.setFont("helvetica", "normal");
            doc.setFontSize(10);
            doc.setTextColor(148, 163, 184); // #94a3b8 (var(--text-muted))
            doc.text(`Original File: ${origName}`, 15, 27);
            doc.text(`Redacted on: ${new Date().toLocaleString()}`, 15, 32);
            
            // Draw a separator line
            doc.setDrawColor(241, 245, 249); // slate-100
            doc.setLineWidth(0.5);
            doc.line(15, 36, 195, 36);
            
            // Add redacted content in a clean monospace font to preserve formatting
            doc.setFont("courier", "normal");
            doc.setFontSize(9);
            doc.setTextColor(30, 41, 59); // slate-800
            
            // Split text to page width (180mm max content width)
            const splitText = doc.splitTextToSize(state.currentDoc.redacted_text, 180);
            let y = 44;
            const pageHeight = doc.internal.pageSize.height;
            
            for (let i = 0; i < splitText.length; i++) {
                if (y + 6 > pageHeight - 15) {
                    doc.addPage();
                    y = 15;
                }
                doc.text(splitText[i], 15, y);
                y += 5.5; // line height
            }
            
            doc.save(newName);
        } catch (error) {
            console.error("PDF generation failed:", error);
            alert("Failed to generate PDF. Downloading as TXT instead.");
            downloadTxt();
        }
    });

    // 2. Download as TXT
    function downloadTxt() {
        if (!state.currentDoc) return;
        
        const origName = state.currentDoc.file_name;
        const nameParts = origName.split(".");
        nameParts.pop();
        const baseName = nameParts.join(".");
        const newName = `redacted_${baseName}.txt`;

        const blob = new Blob([state.currentDoc.redacted_text], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement("a");
        a.href = url;
        a.download = newName;
        document.body.appendChild(a);
        a.click();
        
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
    downloadTxtBtn.addEventListener("click", downloadTxt);

    // 3. Download as CSV
    downloadCsvBtn.addEventListener("click", () => {
        if (!state.currentDoc || !state.currentDoc.structured_data) return;
        
        const origName = state.currentDoc.file_name;
        const nameParts = origName.split(".");
        nameParts.pop();
        const baseName = nameParts.join(".");
        const newName = `redacted_${baseName}.csv`;

        try {
            // Sort findings by length descending to avoid subset replacements
            const sortedFindings = [...state.currentDoc.findings].sort((a, b) => b.value.length - a.value.length);
            
            // Build redaction map
            const entity_counts = {};
            const replacementMap = new Map();
            
            sortedFindings.forEach(f => {
                const val = f.value;
                const f_type = f.type.toUpperCase().replace(/\s+/g, "_");
                if (!replacementMap.has(val)) {
                    entity_counts[f_type] = (entity_counts[f_type] || 0) + 1;
                    replacementMap.set(val, `[REDACTED_${f_type}_${entity_counts[f_type]}]`);
                }
            });

            // Redact cell values in structured data
            const redactedRows = state.currentDoc.structured_data.map(row => {
                const newRow = {};
                for (let [key, val] of Object.entries(row)) {
                    if (val === null || val === undefined) {
                        newRow[key] = "";
                        continue;
                    }
                    let valStr = String(val);
                    replacementMap.forEach((replacement, sensitiveVal) => {
                        valStr = valStr.split(sensitiveVal).join(replacement);
                    });
                    newRow[key] = valStr;
                }
                return newRow;
            });

            // Convert back to CSV format
            const headers = Object.keys(state.currentDoc.structured_data[0]);
            const csvRows = [headers.join(",")];
            
            redactedRows.forEach(row => {
                const values = headers.map(header => {
                    const val = row[header];
                    const CleanVal = String(val).replace(/"/g, '""');
                    return /[,\n"]/.test(CleanVal) ? `"${CleanVal}"` : CleanVal;
                });
                csvRows.push(values.join(","));
            });
            
            const csvContent = csvRows.join("\n");
            const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8" });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement("a");
            a.href = url;
            a.download = newName;
            document.body.appendChild(a);
            a.click();
            
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (error) {
            console.error("CSV generation failed:", error);
            alert("Failed to export as CSV. Downloading raw text instead.");
            downloadTxt();
        }
    });


    // --- 7. Fetch Audit Logs ---
    async function loadAuditLogs() {
        try {
            const response = await fetch("/api/logs", {
                headers: {
                    "Authorization": `Bearer ${state.token}`
                }
            });
            if (!response.ok) throw new Error("Could not load security logs.");

            const data = await response.json();
            
            auditTableBody.innerHTML = "";
            if (data.logs.length === 0) {
                auditTableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No audit records found.</td></tr>`;
            } else {
                data.logs.forEach(log => {
                    const tr = document.createElement("tr");
                    const date = new Date(log.timestamp).toLocaleString();
                    const actionClass = getActionBadgeClass(log.action);
                    const riskClass = log.risk_level === "High" ? "badge-high" : (log.risk_level === "Medium" ? "badge-med" : "badge-low");
                    
                    tr.innerHTML = `
                        <td style="font-size: 11px; white-space: nowrap;">${date}</td>
                        <td><span class="badge ${actionClass}">${log.action.replace("_", " ")}</span></td>
                        <td>${log.file_name || "-"}</td>
                        <td>${log.file_type ? log.file_type.toUpperCase() : "-"}</td>
                        <td><span class="badge ${riskClass}">${log.risk_level || "None"}</span></td>
                        <td><strong>${log.risk_score !== null ? log.risk_score : "-"}</strong></td>
                        <td style="text-align: center;">${log.findings_count !== null ? log.findings_count : "-"}</td>
                        <td style="font-size: 12px; color: var(--text-secondary); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHTML(log.details || '')}">${escapeHTML(log.details || "-")}</td>
                    `;
                    auditTableBody.appendChild(tr);
                });
            }

        } catch (error) {
            loggerError(error);
            auditTableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--color-high);">⚠️ Failed to load audit history: ${error.message}</td></tr>`;
        }
    }

    btnRefreshLogs.addEventListener("click", loadAuditLogs);

    function getActionBadgeClass(action) {
        switch (action) {
            case "DOCUMENT_UPLOAD": return "badge-regex";
            case "Q&A_QUERY": return "badge-ai";
            case "REDACT_DOCUMENT": return "badge-med";
            default: return "badge-low";
        }
    }


    // --- 8. Helper Functions ---
    function escapeHTML(str) {
        if (!str) return "";
        return str.replace(/[&<>'"]/g, 
            tag => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                "'": '&#39;',
                '"': '&quot;'
            }[tag] || tag)
        );
    }

    function formatMarkdown(text) {
        if (!text) return "";
        // Simple regex markdown renderer for code blocks, bold text, bullet items, and spacing
        let html = escapeHTML(text);
        
        // Bold markdown: **text**
        html = html.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
        
        // Inline code markdown: `code`
        html = html.replace(/`(.*?)`/g, "<code>$1</code>");
        
        // Bullet lists: * item or - item at line start
        const lines = html.split("\n");
        let inList = false;
        const formattedLines = lines.map(line => {
            const cleanLine = line.trim();
            if (cleanLine.startsWith("* ") || cleanLine.startsWith("- ")) {
                let content = cleanLine.substring(2);
                let out = "";
                if (!inList) {
                    out += '<ul style="margin-left: 20px; margin-top: 5px; margin-bottom: 5px;">';
                    inList = true;
                }
                out += `<li>${content}</li>`;
                return out;
            } else {
                let out = "";
                if (inList) {
                    out += "</ul>";
                    inList = false;
                }
                out += `<p>${line}</p>`;
                return out;
            }
        });
        
        html = formattedLines.join("");
        if (inList) html += "</ul>";

        // Double spacing back to normal paragraph elements
        html = html.replace(/<p><\/p>/g, "");
        
        return html;
    }

    function loggerError(err) {
        console.error("[ShieldAudit AI ERROR]:", err);
    }

    // Auto-adjust chat input text area height
    chatInput.addEventListener("input", () => {
        chatInput.style.height = "auto";
        chatInput.style.height = (chatInput.scrollHeight) + "px";
    });

    // Initialize Page
    checkAuth();
});
