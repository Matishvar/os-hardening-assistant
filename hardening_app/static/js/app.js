// Read Django serialized rules from script tag
let rulesData = { windows: [], linux: [], android: [] };
try {
  const jsonElement = document.getElementById("django-rules-data");
  if (jsonElement) {
    rulesData = JSON.parse(jsonElement.textContent);
  }
} catch (e) {
  console.error("Failed to parse Django rules database", e);
}

// Global UI state
const state = {
  selectedPlatform: "windows",
  expandedRuleId: null,
  searchTerm: "",
  activeCategoryFilter: "all"
};

// DOM elements cache
let elements = {};

function getOrCreateDeviceId() {
  let deviceId = localStorage.getItem("assistant_device_id");
  if (!deviceId) {
    deviceId = 'device_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    localStorage.setItem("assistant_device_id", deviceId);
  }
  return deviceId;
}

function init() {
  cacheDOMElements();
  
  // Set default platform based on mobile client detection (if on Android phone, select Android)
  const isMobile = /Android/i.test(navigator.userAgent);
  if (isMobile) {
    state.selectedPlatform = "android";
    if (elements.platformTabs) {
      elements.platformTabs.querySelectorAll(".platform-btn").forEach(btn => {
        if (btn.dataset.platform === "android") {
          btn.classList.add("active");
        } else {
          btn.classList.remove("active");
        }
      });
    }
  }
  
  // Append device_id to History sidebar link to separate log queries
  const deviceId = getOrCreateDeviceId();
  const historyLink = document.getElementById("history-menu-item");
  if (historyLink) {
    const baseHref = historyLink.getAttribute('href');
    historyLink.href = baseHref.includes('?') ? baseHref : `${baseHref}?device_id=${deviceId}`;
  }
  
  bindEvents();
  if (elements.filterGroup) renderFilters();
  if (elements.checklist) renderChecklist();
  if (elements.progressValue) updateDashboard();
  if (elements.codeViewer) generateScriptPreview();
}

function cacheDOMElements() {
  elements = {
    platformTabs: document.getElementById("platform-tabs"),
    searchBox: document.getElementById("search-input"),
    filterGroup: document.getElementById("filter-group"),
    checklist: document.getElementById("checklist"),
    codeViewer: document.getElementById("code-viewer"),
    fileName: document.getElementById("file-name"),
    progressValue: document.getElementById("progress-value"),
    completedValue: document.getElementById("completed-value"),
    pendingValue: document.getElementById("pending-value"),
    copyBtn: document.getElementById("copy-btn"),
    downloadBtn: document.getElementById("download-btn"),
    toggleAllCheckboxesBtn: document.getElementById("toggle-all-checkboxes"),
    toggleAllScriptBtn: document.getElementById("toggle-all-script"),
    toast: document.getElementById("toast"),
    csrfInput: document.getElementById("csrf-token"),
    
    // Scanner elements
    scanBtn: document.getElementById("scan-btn"),
    loadingOverlay: document.getElementById("loading-overlay"),
    reportModal: document.getElementById("report-modal"),
    closeModalBtn: document.getElementById("close-modal-btn"),
    
    // Report fields
    reportPlatformTitle: document.getElementById("report-platform-title"),
    reportTimestamp: document.getElementById("report-timestamp"),
    reportBeforeScore: document.getElementById("report-before-score"),
    reportAfterScore: document.getElementById("report-after-score"),
    downloadPdfBtn: document.getElementById("download-pdf-btn"),
    scoreShiftBar: document.getElementById("score-shift-bar"),
    shiftSummary: document.getElementById("shift-summary"),
    reportResolvedList: document.getElementById("report-resolved-list"),
    reportFailedList: document.getElementById("report-failed-list")
  };
}

function getCsrfToken() {
  return elements.csrfInput ? elements.csrfInput.value : "";
}

function bindEvents() {
  // Platform switching tabs
  if (elements.platformTabs) {
    elements.platformTabs.addEventListener("click", (e) => {
      const btn = e.target.closest(".platform-btn");
      if (!btn || btn.classList.contains("active")) return;
      
      elements.platformTabs.querySelectorAll(".platform-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      
      state.selectedPlatform = btn.dataset.platform;
      state.expandedRuleId = null;
      state.activeCategoryFilter = "all";
      
      if (elements.filterGroup) renderFilters();
      if (elements.checklist) renderChecklist();
      updateDashboard();
      generateScriptPreview();
    });
  }

  // Search input matching
  if (elements.searchBox) {
    elements.searchBox.addEventListener("input", (e) => {
      state.searchTerm = e.target.value.toLowerCase();
      renderChecklist();
    });
  }

  // Filter category buttons
  if (elements.filterGroup) {
    elements.filterGroup.addEventListener("click", (e) => {
      const btn = e.target.closest(".filter-btn");
      if (!btn) return;
      
      elements.filterGroup.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      
      state.activeCategoryFilter = btn.dataset.category;
      renderChecklist();
    });
  }

  // Bulk Checks toggle
  if (elements.toggleAllCheckboxesBtn) {
    elements.toggleAllCheckboxesBtn.addEventListener("click", async () => {
      const visible = getFilteredRules();
      if (visible.length === 0) return;
      
      const hasUnchecked = visible.some(r => !r.isCompleted);
      const action = hasUnchecked ? 'check_all' : 'uncheck_all';
      
      try {
        const response = await fetch('/api/bulk-actions/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
          },
          body: JSON.stringify({
            platform: state.selectedPlatform,
            action: action,
            category: state.activeCategoryFilter
          })
        });
        
        const res = await response.json();
        if (res.success) {
          visible.forEach(r => {
            r.isCompleted = hasUnchecked;
          });
          renderChecklist();
          updateDashboard();
          showToast(hasUnchecked ? "Checked all visible items" : "Unchecked all visible items");
        } else {
          showToast("Error executing bulk action: " + res.error, true);
        }
      } catch (err) {
        showToast("Network error: " + err, true);
      }
    });
  }

  // Bulk Scripts toggle
  if (elements.toggleAllScriptBtn) {
    elements.toggleAllScriptBtn.addEventListener("click", async () => {
      const visible = getFilteredRules();
      if (visible.length === 0) return;
      
      const hasExcluded = visible.some(r => !r.isIncluded);
      const action = hasExcluded ? 'include_all' : 'exclude_all';
      
      try {
        const response = await fetch('/api/bulk-actions/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
          },
          body: JSON.stringify({
            platform: state.selectedPlatform,
            action: action,
            category: state.activeCategoryFilter
          })
        });
        
        const res = await response.json();
        if (res.success) {
          visible.forEach(r => {
            r.isIncluded = hasExcluded;
          });
          renderChecklist();
          generateScriptPreview();
          showToast(hasExcluded ? "Included all visible scripts" : "Excluded all visible scripts");
        } else {
          showToast("Error executing bulk action: " + res.error, true);
        }
      } catch (err) {
        showToast("Network error: " + err, true);
      }
    });
  }

  // Copy code to Clipboard
  if (elements.copyBtn) {
    elements.copyBtn.addEventListener("click", () => {
      if (!elements.codeViewer) return;
      navigator.clipboard.writeText(elements.codeViewer.value).then(() => {
        showToast("Script copied to clipboard!");
      }).catch(err => {
        showToast("Copy failed: " + err, true);
      });
    });
  }

  // Download script file from Django backend
  if (elements.downloadBtn) {
    elements.downloadBtn.addEventListener("click", () => {
      window.location.href = `/download-script/${state.selectedPlatform}/`;
      showToast("Downloading file...");
    });
  }

  // --- Automated Scanner Actions ---

  if (elements.scanBtn) {
    elements.scanBtn.addEventListener("click", async () => {
      if (elements.loadingOverlay) elements.loadingOverlay.classList.add("active");
      
      try {
        const response = await fetch('/api/scan/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
          },
          body: JSON.stringify({
            platform: state.selectedPlatform,
            device_id: getOrCreateDeviceId()
          })
        });
        
        const res = await response.json();
        if (elements.loadingOverlay) elements.loadingOverlay.classList.remove("active");
        
        if (res.success) {
          const report = res.report;
          
          // Save scan details to client side localStorage
          saveScanToHistory(state.selectedPlatform, report.after_score, report.timestamp);
          
          // Populate modal report fields if available
          if (elements.reportPlatformTitle) {
            elements.reportPlatformTitle.textContent = state.selectedPlatform.toUpperCase();
          }
          if (elements.reportTimestamp) elements.reportTimestamp.textContent = report.timestamp;
          if (elements.reportBeforeScore) elements.reportBeforeScore.textContent = `${report.before_score}%`;
          if (elements.reportAfterScore) elements.reportAfterScore.textContent = `${report.after_score}%`;
          
          // Update PDF download link href for the specific platform
          if (elements.downloadPdfBtn) {
            elements.downloadPdfBtn.href = `/api/download-pdf/${state.selectedPlatform}/`;
          }
          
          // Update shift indicator bar
          if (elements.scoreShiftBar) {
            elements.scoreShiftBar.style.width = `${report.after_score}%`;
          }
          
          // Score difference summary
          if (elements.shiftSummary) {
            const diff = report.after_score - report.before_score;
            const sign = diff >= 0 ? "+" : "";
            elements.shiftSummary.textContent = `${state.selectedPlatform.toUpperCase()} compliance score changed by ${sign}${diff}%`;
          }
          
          // Populate resolved rules list
          if (elements.reportResolvedList) {
            if (report.resolved_rules.length === 0) {
              elements.reportResolvedList.innerHTML = "<li>No new controls resolved in this scan.</li>";
            } else {
              elements.reportResolvedList.innerHTML = report.resolved_rules
                .map(title => `<li>${title}</li>`).join("");
            }
          }
          
          // Populate remaining vulnerability list
          if (elements.reportFailedList) {
            if (report.still_failed_rules.length === 0) {
              elements.reportFailedList.innerHTML = "<li style='color: var(--success);'>All checks passed! System fully compliant.</li>";
            } else {
              elements.reportFailedList.innerHTML = report.still_failed_rules
                .map(title => `<li>${title}</li>`).join("");
            }
          }
          
          // Open report modal
          if (elements.reportModal) elements.reportModal.classList.add("active");
        } else {
          showToast("Scan failed: " + res.error, true);
        }
      } catch (err) {
        if (elements.loadingOverlay) elements.loadingOverlay.classList.remove("active");
        showToast("Network error executing scan: " + err, true);
      }
    });
  }

  // Close report modal and refresh page to load new DB state
  if (elements.closeModalBtn) {
    elements.closeModalBtn.addEventListener("click", () => {
      if (elements.reportModal) elements.reportModal.classList.remove("active");
      window.location.reload();
    });
  }
  
  // Close modal when clicking background overlay
  if (elements.reportModal) {
    elements.reportModal.addEventListener("click", (e) => {
      if (e.target === elements.reportModal) {
        elements.reportModal.classList.remove("active");
        window.location.reload();
      }
    });
  }
}

function getFilteredRules() {
  const allRules = rulesData[state.selectedPlatform] || [];
  return allRules.filter(rule => {
    const matchesSearch = rule.title.toLowerCase().includes(state.searchTerm) || 
                          rule.description.toLowerCase().includes(state.searchTerm) ||
                          rule.rationale.toLowerCase().includes(state.searchTerm);
    const matchesCategory = state.activeCategoryFilter === "all" || rule.category === state.activeCategoryFilter;
    return matchesSearch && matchesCategory;
  });
}

function renderFilters() {
  if (!elements.filterGroup) return;
  const allRules = rulesData[state.selectedPlatform] || [];
  const categories = ["all", ...new Set(allRules.map(r => r.category))];
  
  elements.filterGroup.innerHTML = categories.map(cat => {
    const isActive = cat === state.activeCategoryFilter;
    return `
      <button class="filter-btn ${isActive ? 'active' : ''}" data-category="${cat}">
        ${cat.charAt(0).toUpperCase() + cat.slice(1)}
      </button>
    `;
  }).join("");
}

function renderChecklist() {
  if (!elements.checklist) return;
  const filtered = getFilteredRules();
  
  if (filtered.length === 0) {
    elements.checklist.innerHTML = `
      <div class="empty-state glass-panel">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <h4>No security rules found</h4>
        <p>Try refining your search terms or selecting another category.</p>
      </div>
    `;
    return;
  }

  elements.checklist.innerHTML = filtered.map(rule => {
    const isChecked = rule.isCompleted;
    const isIncluded = rule.isIncluded;
    const isExpanded = state.expandedRuleId === rule.id;
    
    return `
      <div class="checklist-item glass-panel ${isChecked ? 'checked' : ''} ${isExpanded ? 'expanded' : ''}" data-id="${rule.id}">
        <div class="checklist-item-header">
          <div class="custom-checkbox" onclick="toggleCheck('${rule.id}', event)">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <div class="checklist-item-title-desc" onclick="toggleExpand('${rule.id}')">
            <h3>${rule.title}</h3>
            <p>${rule.description}</p>
          </div>
          <div class="meta-badges">
            <span class="badge category">${rule.category}</span>
            <span class="badge severity-${rule.severity}">${rule.severity}</span>
          </div>
        </div>
        
        <div class="checklist-item-details">
          <div class="detail-section">
            <h4>Rationale</h4>
            <p>${rule.rationale}</p>
          </div>
          <div class="detail-section">
            <h4>Verification Command</h4>
            <div class="code-box verification">${escapeHtml(rule.verification)}</div>
          </div>
          <div class="detail-section">
            <h4>Manual Remediation</h4>
            <div class="code-box">${escapeHtml(rule.remediation)}</div>
          </div>
          <div class="script-toggle-section" onclick="event.stopPropagation()">
            <span>Include in Generated Security Script</span>
            <label class="switch">
              <input type="checkbox" ${isIncluded ? 'checked' : ''} onchange="toggleScriptInclusion('${rule.id}', this.checked)">
              <span class="slider"></span>
            </label>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

// Checkbox click event -> Sync with Django API
window.toggleCheck = async function(id, event) {
  event.stopPropagation();
  
  const rules = rulesData[state.selectedPlatform] || [];
  const rule = rules.find(r => r.id === id);
  if (!rule) return;
  
  try {
    const response = await fetch('/api/toggle-complete/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken()
      },
      body: JSON.stringify({ rule_id: id })
    });
    
    const res = await response.json();
    if (res.success) {
      rule.isCompleted = res.is_completed;
      
      const card = document.querySelector(`.checklist-item[data-id="${id}"]`);
      if (card) {
        if (rule.isCompleted) {
          card.classList.add("checked");
        } else {
          card.classList.remove("checked");
        }
      }
      
      updateDashboard();
      showToast(rule.isCompleted ? "Rule checked off" : "Rule marked pending");
    } else {
      showToast("Error updating database: " + res.error, true);
    }
  } catch (err) {
    showToast("Network error: " + err, true);
  }
};

window.toggleExpand = function(id) {
  state.expandedRuleId = state.expandedRuleId === id ? null : id;
  
  document.querySelectorAll(".checklist-item").forEach(card => {
    const cardId = card.dataset.id;
    if (cardId === state.expandedRuleId) {
      card.classList.add("expanded");
    } else {
      card.classList.remove("expanded");
    }
  });
};

// Script toggle event -> Sync with Django API
window.toggleScriptInclusion = async function(id, checked) {
  const rules = rulesData[state.selectedPlatform] || [];
  const rule = rules.find(r => r.id === id);
  if (!rule) return;
  
  try {
    const response = await fetch('/api/toggle-include/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken()
      },
      body: JSON.stringify({ rule_id: id })
    });
    
    const res = await response.json();
    if (res.success) {
      rule.isIncluded = res.is_included;
      generateScriptPreview();
      showToast(rule.isIncluded ? "Script step enabled" : "Script step disabled");
    } else {
      showToast("Error updating script configuration: " + res.error, true);
    }
  } catch (err) {
    showToast("Network error: " + err, true);
  }
};

function updateDashboard() {
  if (!elements.progressValue) return;
  const rules = rulesData[state.selectedPlatform] || [];
  const total = rules.length;
  const completed = rules.filter(r => r.isCompleted).length;
  const pending = total - completed;
  const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;
  
  if (elements.progressValue) elements.progressValue.textContent = `${percentage}%`;
  if (elements.completedValue) elements.completedValue.textContent = completed;
  if (elements.pendingValue) elements.pendingValue.textContent = pending;
  
  // Trigger layout updates on dashboard page custom script blocks
  if (window.updateDashboard && window.updateDashboard !== updateDashboard) {
    // Intercept to avoid recursion
  }
}

function generateScriptPreview() {
  if (!elements.codeViewer) return;
  const isWin = state.selectedPlatform === "windows";
  const isLin = state.selectedPlatform === "linux";
  
  if (elements.fileName) {
    if (isWin) {
      elements.fileName.textContent = "win-hardening.ps1";
    } else if (isLin) {
      elements.fileName.textContent = "linux-hardening.sh";
    } else {
      elements.fileName.textContent = "android-hardening.sh";
    }
  }
  
  const rules = rulesData[state.selectedPlatform] || [];
  const selectedRules = rules.filter(r => r.isIncluded);
  
  let scriptText = "";
  const dateStr = new Date().toISOString().split('T')[0];

  if (isWin) {
    scriptText += `<#
.SYNOPSIS
    Custom OS Hardening Script generated by OS Hardening Assistant.
    Platform: Windows
    Generated on: ${dateStr}
.DESCRIPTION
    This script implements selected system hardening controls. Ensure you run this in an Elevated PowerShell Console.
#>

# Check for administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Please relaunch PowerShell with administrative privileges."
    Exit 1
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Starting Windows System Hardening Script " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Running check implementations...        " -ForegroundColor Gray
Write-Host "==========================================" -ForegroundColor Cyan
`;
    
    if (selectedRules.length === 0) {
      scriptText += "\n# No hardening scripts selected to run.\n";
    } else {
      selectedRules.forEach(rule => {
        scriptText += `\n${rule.scriptCode}\n`;
      });
    }
    
    scriptText += `\nWrite-Host "==========================================" -ForegroundColor Cyan
Write-Host " Hardening script run finished!           " -ForegroundColor Cyan
Write-Host " Please reboot system if required.        " -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan
`;
  } else if (isLin) {
    scriptText += `#!/bin/bash
# ==============================================================================
# Custom OS Hardening Script generated by OS Hardening Assistant
# Platform: Linux (Ubuntu/Debian)
# Generated on: ${dateStr}
# ==============================================================================

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root (sudo)." >&2
  exit 1
fi

echo "=========================================="
echo " Starting Linux System Hardening Script   "
echo "=========================================="

# Backup configuration helper function
backup_file() {
    local filepath="$1"
    if [ -f "$filepath" ] && [ ! -f "\text{filepath}.bak" ]; then
        echo "Creating backup of \$filepath to \${filepath}.bak"
        cp "\$filepath" "\${filepath}.bak"
    fi
}
`;

    if (selectedRules.length === 0) {
      scriptText += "\n# No hardening scripts selected to run.\n";
    } else {
      selectedRules.forEach(rule => {
        scriptText += `\n${rule.scriptCode}\n`;
      });
    }

    scriptText += `\necho "=========================================="
echo " Hardening script run finished!           "
echo " Please check logs above & reboot if needed."
echo "=========================================="
`;
  } else {
    // Android platform ADB scripts
    scriptText += `#!/bin/bash
# ==============================================================================
# Custom Android ADB Hardening Script generated by OS Hardening Assistant
# Platform: Android (Audited via ADB Commands)
# Generated on: ${dateStr}
# ==============================================================================

echo "=========================================="
echo " Starting Android ADB Hardening Controls  "
echo " Ensure USB Debugging is active on phone  "
echo "=========================================="

# Helper function to check adb connection
check_adb() {
    adb devices | grep -w "device" > /dev/null
    if [ $? -ne 0 ]; then
        echo "Error: No Android device authorized via ADB. Please connect and verify permissions."
        exit 1
    fi
}

check_adb
`;

    if (selectedRules.length === 0) {
      scriptText += "\n# No hardening ADB scripts selected to run.\n";
    } else {
      selectedRules.forEach(rule => {
        if (!rule.scriptCode.startsWith("#")) {
          scriptText += `\necho 'Applying control: ${rule.title}'\n${rule.scriptCode}\n`;
        } else {
          scriptText += `\n# ${rule.title} - ${rule.remediation}\n`;
        }
      });
    }

    scriptText += `\necho "=========================================="
echo " Android Hardening settings applied!      "
echo "=========================================="
`;
  }

  elements.codeViewer.value = scriptText;
}

function showToast(message, isError = false) {
  if (!elements.toast) return;
  const toastText = elements.toast.querySelector("span");
  if (toastText) toastText.textContent = message;
  
  elements.toast.style.background = isError ? "var(--danger)" : "var(--success)";
  elements.toast.style.boxShadow = isError ? "0 10px 25px rgba(239,68,68,0.3)" : "0 10px 25px rgba(16,185,129,0.3)";
  elements.toast.classList.add("show");
  
  setTimeout(() => {
    elements.toast.classList.remove("show");
  }, 3000);
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function saveScanToHistory(platform, score, timestamp) {
  let history = [];
  try {
    history = JSON.parse(localStorage.getItem("assistant_scan_history") || "[]");
  } catch (e) {
    console.error("Failed to parse scan history", e);
  }
  
  history.unshift({
    platform: platform,
    score: score,
    timestamp: timestamp || new Date().toLocaleString()
  });
  
  if (history.length > 50) {
    history = history.slice(0, 50);
  }
  
  localStorage.setItem("assistant_scan_history", JSON.stringify(history));
}

function renderHistoryFromLocalStorage() {
  const tbody = document.getElementById("history-logs-tbody");
  if (!tbody) return;
  
  let history = [];
  try {
    history = JSON.parse(localStorage.getItem("assistant_scan_history") || "[]");
  } catch (e) {
    console.error("Failed to read scan history", e);
  }
  
  if (history.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="4" style="text-align: center; padding: 4rem; color: var(--text-secondary);">
          <div style="font-size: 2.5rem; margin-bottom: 0.75rem;">📁</div>
          <h4 style="font-weight: 600; color: var(--text-primary); margin-bottom: 0.25rem;">No scans recorded yet</h4>
          <p style="font-size: 0.85rem; color: var(--text-secondary);">Audit your configurations on the dashboard to register a security record.</p>
        </td>
      </tr>
    `;
    return;
  }
  
  tbody.innerHTML = history.map(report => {
    const platformLabel = report.platform === 'windows' ? '💻 WINDOWS OS' : (report.platform === 'linux' ? '🐧 LINUX OS' : '📱 ANDROID OS');
    const scoreColor = report.score >= 80 ? 'var(--success)' : (report.score >= 50 ? 'var(--warning)' : 'var(--danger)');
    
    return `
      <tr style="border-bottom: 1px solid var(--panel-border); transition: background var(--transition-fast);">
        <td style="padding: 1.2rem 1.5rem; font-family: var(--font-mono); font-size: 0.88rem; color: var(--text-primary);">
          ${report.timestamp}
        </td>
        <td style="padding: 1.2rem 1.5rem;">
          <span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--panel-border); font-size: 0.72rem; padding: 0.25rem 0.75rem; border-radius: 30px;">
            ${platformLabel}
          </span>
        </td>
        <td style="padding: 1.2rem 1.5rem; font-weight: 700; font-size: 1.1rem; color: ${scoreColor};">
          ${report.score}%
        </td>
        <td style="padding: 1.2rem 1.5rem; text-align: right;">
          <a href="/api/download-pdf/${report.platform}/" class="primary-btn" style="display: inline-flex; text-decoration: none; padding: 0.45rem 1.2rem; font-size: 0.8rem; background: linear-gradient(135deg, #10b981 0%, #059669 100%); font-weight: 600; border-radius: var(--radius-sm); align-items: center; gap: 0.25rem; box-shadow: 0 4px 12px rgba(16, 185, 129, 0.15);" title="Download compiled PDF certificate for this run">
            <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" style="vertical-align: middle; margin-right: 0.25rem;">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            Download PDF
          </a>
        </td>
      </tr>
    `;
  }).join("");
}

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  init();
  renderHistoryFromLocalStorage();
});
