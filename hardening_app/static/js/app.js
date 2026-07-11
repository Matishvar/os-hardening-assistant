// Read Django serialized rules from script tag
let rulesData = { windows: [], linux: [] };
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

function init() {
  cacheDOMElements();
  bindEvents();
  renderFilters();
  renderChecklist();
  updateDashboard();
  generateScriptPreview();
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
    csrfInput: document.getElementById("csrf-token")
  };
}

function getCsrfToken() {
  return elements.csrfInput ? elements.csrfInput.value : "";
}

function bindEvents() {
  // Platform switching tabs
  elements.platformTabs.addEventListener("click", (e) => {
    const btn = e.target.closest(".platform-btn");
    if (!btn || btn.classList.contains("active")) return;
    
    elements.platformTabs.querySelectorAll(".platform-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    
    state.selectedPlatform = btn.dataset.platform;
    state.expandedRuleId = null;
    state.activeCategoryFilter = "all";
    
    renderFilters();
    renderChecklist();
    updateDashboard();
    generateScriptPreview();
  });

  // Search input matching
  elements.searchBox.addEventListener("input", (e) => {
    state.searchTerm = e.target.value.toLowerCase();
    renderChecklist();
  });

  // Filter category buttons
  elements.filterGroup.addEventListener("click", (e) => {
    const btn = e.target.closest(".filter-btn");
    if (!btn) return;
    
    elements.filterGroup.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    
    state.activeCategoryFilter = btn.dataset.category;
    renderChecklist();
  });

  // Bulk Checks toggle
  elements.toggleAllCheckboxesBtn.addEventListener("click", async () => {
    const visible = getFilteredRules();
    if (visible.length === 0) return;
    
    // Determine if we should check all or uncheck all
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
        // Update local memory state
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

  // Bulk Scripts toggle
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
        // Update local memory state
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

  // Copy code to Clipboard
  elements.copyBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(elements.codeViewer.value).then(() => {
      showToast("Script copied to clipboard!");
    }).catch(err => {
      showToast("Copy failed: " + err, true);
    });
  });

  // Download script file from Django backend
  elements.downloadBtn.addEventListener("click", () => {
    window.location.href = `/download-script/${state.selectedPlatform}/`;
    showToast("Downloading file...");
  });
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
      
      // Update element class directly
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
  const rules = rulesData[state.selectedPlatform] || [];
  const total = rules.length;
  const completed = rules.filter(r => r.isCompleted).length;
  const pending = total - completed;
  const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;
  
  elements.progressValue.textContent = `${percentage}%`;
  elements.completedValue.textContent = completed;
  elements.pendingValue.textContent = pending;
}

function generateScriptPreview() {
  const isWin = state.selectedPlatform === "windows";
  elements.fileName.textContent = isWin ? "win-hardening.ps1" : "linux-hardening.sh";
  
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
  } else {
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
    if [ -f "$filepath" ] && [ ! -f "\${filepath}.bak" ]; then
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
  }

  elements.codeViewer.value = scriptText;
}

function showToast(message, isError = false) {
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

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  init();
});
