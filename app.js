// Hardening Rules Database
const HARDENING_RULES = {
  windows: [
    {
      id: "win-guest-acct",
      title: "Disable Guest Account",
      category: "Accounts",
      severity: "critical",
      description: "Deactivates the built-in Guest account to prevent unauthorized, anonymous logins.",
      rationale: "The default Guest account has no password by default and can allow a physical or network attacker to access system files or obtain a local user profile without authentication.",
      verification: "Get-LocalUser -Name \"Guest\" | Select-Object Enabled",
      remediation: "Disable-LocalUser -Name \"Guest\"",
      scriptCode: `# Rule: Disable Guest Account
Write-Host "[-] Disabling Guest account..." -ForegroundColor Gray
try {
    Disable-LocalUser -Name "Guest" -ErrorAction Stop
    Write-Host "[+] Guest account disabled successfully." -ForegroundColor Green
} catch {
    Write-Warning "Failed to disable Guest account: $_"
}`
    },
    {
      id: "win-pw-length",
      title: "Enforce Minimum Password Length (14 chars)",
      category: "Accounts",
      severity: "high",
      description: "Sets the minimum length requirement for all local account passwords to 14 characters.",
      rationale: "Longer passwords exponentially increase the work required to crack them via brute force or dictionary attacks. Industry standards (like CIS and NIST) recommend a minimum of 14 characters.",
      verification: "net accounts (Look for 'Minimum password length')",
      remediation: "net accounts /minpwlen:14",
      scriptCode: `# Rule: Enforce Minimum Password Length (14 characters)
Write-Host "[-] Configuring minimum password length to 14..." -ForegroundColor Gray
try {
    net accounts /minpwlen:14
    Write-Host "[+] Password length requirement enforced." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set password length: $_"
}`
    },
    {
      id: "win-defender-rt",
      title: "Enable Windows Defender Real-Time Protection",
      category: "Antivirus",
      severity: "critical",
      description: "Ensures Microsoft Defender Antivirus actively scans for malware and threats in real-time.",
      rationale: "Real-time monitoring detects and blocks threats during execution, file creation, or download before they can compromise the system.",
      verification: "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled",
      remediation: "Set-MpPreference -DisableRealtimeMonitoring $false",
      scriptCode: `# Rule: Enable Microsoft Defender Real-Time Protection
Write-Host "[-] Enabling Microsoft Defender Real-Time Protection..." -ForegroundColor Gray
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Write-Host "[+] Defender Real-Time Protection enabled." -ForegroundColor Green
} catch {
    Write-Warning "Failed to enable Defender Real-Time Protection: $_"
}`
    },
    {
      id: "win-firewall-profiles",
      title: "Enable Firewall & Block Default Inbound",
      category: "Network",
      severity: "high",
      description: "Enables Windows Defender Firewall on all profiles (Domain, Private, Public) and sets default incoming behavior to Block.",
      rationale: "A running host-based firewall is a primary defense line. Default-blocking all incoming traffic ensures that only explicitly whitelisted services are reachable from outside.",
      verification: "Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction",
      remediation: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block",
      scriptCode: `# Rule: Enable Firewall and set Default Inbound to Block
Write-Host "[-] Configuring Windows Firewall profiles..." -ForegroundColor Gray
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -ErrorAction Stop
    Write-Host "[+] Windows Firewall enabled and inbound traffic blocked by default." -ForegroundColor Green
} catch {
    Write-Warning "Failed to configure Windows Firewall: $_"
}`
    },
    {
      id: "win-disable-llmnr",
      title: "Disable LLMNR (Link-Local Multicast Name Resolution)",
      category: "Network",
      severity: "high",
      description: "Turns off LLMNR to prevent local multicast spoofing attacks.",
      rationale: "LLMNR allows hosts on the same subnet to resolve names without DNS. Attackers can listen for these broadcasts and spoof target names to intercept network hashes and passwords.",
      verification: "Get-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue",
      remediation: "New-Item -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT' -Name 'DNSClient' -Force; New-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force",
      scriptCode: `# Rule: Disable LLMNR via Registry
Write-Host "[-] Disabling LLMNR (Link-Local Multicast Name Resolution)..." -ForegroundColor Gray
try {
    $registryPath = "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient"
    if (-not (Test-Path $registryPath)) {
        New-Item -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows NT" -Name "DNSClient" -Force | Out-Null
    }
    New-ItemProperty -Path $registryPath -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    Write-Host "[+] LLMNR disabled successfully." -ForegroundColor Green
} catch {
    Write-Warning "Failed to disable LLMNR: $_"
}`
    },
    {
      id: "win-smbv1",
      title: "Disable Legacy SMBv1 Protocol",
      category: "Services",
      severity: "critical",
      description: "Disables the highly vulnerable and obsolete Server Message Block v1 protocol.",
      rationale: "SMBv1 is outdated, slow, lacks security improvements like packet signing/encryption, and contains major known vulnerabilities (e.g., EternalBlue, which was used to distribute WannaCry ransomware).",
      verification: "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol",
      remediation: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
      scriptCode: `# Rule: Disable SMBv1 Protocol
Write-Host "[-] Disabling SMBv1 Protocol..." -ForegroundColor Gray
try {
    # Disable SMBv1 server configuration
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    # Disable SMBv1 optional feature
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop | Out-Null
    Write-Host "[+] SMBv1 protocol disabled successfully." -ForegroundColor Green
} catch {
    Write-Warning "Failed to completely disable SMBv1: $_"
}`
    },
    {
      id: "win-uac-always",
      title: "Set UAC to 'Always Notify'",
      category: "System",
      severity: "high",
      description: "Raises User Account Control (UAC) prompts to the maximum level to prevent unauthorized administrator actions.",
      rationale: "With UAC set to 'Always Notify', any administrative change requires explicit manual consent. This prevents background scripts or malwares from silently escalating privileges.",
      verification: "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin'",
      remediation: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2",
      scriptCode: `# Rule: Set UAC to 'Always Notify'
Write-Host "[-] Setting User Account Control (UAC) to Always Notify..." -ForegroundColor Gray
try {
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "PromptOnSecureDesktop" -Value 1 -ErrorAction Stop
    Write-Host "[+] UAC set to Always Notify on Secure Desktop." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set UAC settings: $_"
}`
    },
    {
      id: "win-powershell-policy",
      title: "Set PowerShell Execution Policy to RemoteSigned",
      category: "System",
      severity: "medium",
      description: "Restricts script execution so that downloaded scripts must be signed by a trusted publisher before running.",
      rationale: "Defaulting execution policy to RemoteSigned prevents standard users from easily double-clicking and executing arbitrary untrusted scripts from the internet.",
      verification: "Get-ExecutionPolicy",
      remediation: "Set-ExecutionPolicy RemoteSigned -Force",
      scriptCode: `# Rule: Restrict PowerShell Execution Policy to RemoteSigned
Write-Host "[-] Restricting PowerShell Execution Policy to RemoteSigned..." -ForegroundColor Gray
try {
    Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
    Write-Host "[+] Execution Policy successfully set to RemoteSigned." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set Execution Policy: $_"
}`
    },
    {
      id: "win-audit-logon",
      title: "Enable Auditing for Logon Failures",
      category: "Auditing",
      severity: "medium",
      description: "Enables event log recording for failed logon attempts.",
      rationale: "Audit logs are critical for security monitoring. Logging logon failures allows detection of brute-force campaigns, credential harvesting, or unauthorized local logins.",
      verification: "auditpol /get /subcategory:\"Logon\"",
      remediation: "auditpol /set /subcategory:\"Logon\" /failure:enable",
      scriptCode: `# Rule: Enable Auditing for Logon Failures
Write-Host "[-] Configuring Audit Policy for Logon Failures..." -ForegroundColor Gray
try {
    auditpol /set /subcategory:"Logon" /failure:enable
    Write-Host "[+] Auditing for Logon Failures enabled successfully." -ForegroundColor Green
} catch {
    Write-Warning "Failed to enable logon failure auditing: $_"
}`
    }
  ],
  linux: [
    {
      id: "lin-ssh-root",
      title: "Disable Root Login over SSH",
      category: "Accounts",
      severity: "critical",
      description: "Restricts direct root user access over SSH connection.",
      rationale: "The 'root' user is a universal administrator name across all Linux hosts. Disabling direct root login forces attackers to discover both a customized username and password/key first, preventing direct administrative brute force.",
      verification: "grep -i \"^PermitRootLogin\" /etc/ssh/sshd_config",
      remediation: "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config && sudo systemctl restart sshd",
      scriptCode: `# Rule: Disable Root Login over SSH
echo "[-] Disabling direct root login over SSH..."
if [ -f /etc/ssh/sshd_config ]; then
    backup_file "/etc/ssh/sshd_config"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config
    systemctl restart sshd || systemctl restart ssh
    echo "[+] Root SSH login disabled."
else
    echo "[!] sshd_config not found. Skipping SSH config."
fi`
    },
    {
      id: "lin-ssh-key",
      title: "Enforce SSH Key-Based Authentication Only",
      category: "Accounts",
      severity: "high",
      description: "Disables standard password authentication for SSH logins.",
      rationale: "Passwords are subject to credential stuffing and brute-force attacks. Enforcing keys ensures that only accounts possessing the cryptographic private key can authenticate.",
      verification: "grep -i \"^PasswordAuthentication\" /etc/ssh/sshd_config",
      remediation: "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config && sudo systemctl restart sshd",
      scriptCode: `# Rule: Enforce SSH Key-Based Authentication
echo "[-] Disabling SSH password authentication..."
if [ -f /etc/ssh/sshd_config ]; then
    backup_file "/etc/ssh/sshd_config"
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config
    systemctl restart sshd || systemctl restart ssh
    echo "[+] Password-based SSH logins disabled."
else
    echo "[!] sshd_config not found. Skipping."
fi`
    },
    {
      id: "lin-ufw-setup",
      title: "Configure UFW Firewall Default Policies",
      category: "Network",
      severity: "high",
      description: "Installs UFW (if missing) and sets policy to deny incoming and allow outgoing traffic.",
      rationale: "Default incoming deny posture blocks port scans and unauthorized access to running listening processes. Permitting outgoing traffic allows updates and downloads to continue.",
      verification: "sudo ufw status verbose",
      remediation: "sudo apt-get install -y ufw && sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw enable",
      scriptCode: `# Rule: Configure UFW Firewall Policies
echo "[-] Installing and configuring UFW Firewall..."
if command -v apt-get &> /dev/null; then
    apt-get update -y &> /dev/null
    apt-get install -y ufw &> /dev/null
    ufw default deny incoming
    ufw default allow outgoing
    # Ensure SSH port is open so you don't lock yourself out!
    ufw allow 22/tcp
    ufw --force enable
    echo "[+] UFW configured (default deny incoming, SSH allowed)."
else
    echo "[!] apt-get not found. Cannot configure UFW automatically."
fi`
    },
    {
      id: "lin-secure-shm",
      title: "Secure Shared Memory (/dev/shm)",
      category: "System",
      severity: "medium",
      description: "Mounts /dev/shm with 'noexec, nosuid, nodev' flags to prevent malicious script executions.",
      rationale: "/dev/shm is a shared memory region that acts as a fast temporary drive. Malicious users often write exploits to /dev/shm. Restricting mount flags stops binary executions inside this partition.",
      verification: "mount | grep /dev/shm",
      remediation: "echo 'tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0' | sudo tee -a /etc/fstab && sudo mount -o remount /dev/shm",
      scriptCode: `# Rule: Secure Shared Memory (/dev/shm)
echo "[-] Securing shared memory partition (/dev/shm)..."
if ! grep -q "/dev/shm" /etc/fstab; then
    backup_file "/etc/fstab"
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    mount -o remount /dev/shm &> /dev/null || mount /dev/shm
    echo "[+] Secured shared memory (/dev/shm) in /etc/fstab."
else
    echo "[!] /dev/shm already defined in /etc/fstab."
fi`
    },
    {
      id: "lin-auto-upgrades",
      title: "Enable Automatic Security Updates",
      category: "System",
      severity: "high",
      description: "Enables 'unattended-upgrades' to automatically patch security vulnerabilities.",
      rationale: "Keeping packages patched is critical. Outdated dependencies leave systems open to known public CVEs. Auto-upgrades apply safety patches as soon as they release.",
      verification: "cat /etc/apt/apt.conf.d/20auto-upgrades",
      remediation: "sudo apt-get install -y unattended-upgrades && echo -e \"APT::Periodic::Update-Package-Lists \\\"1\\\";\\nAPT::Periodic::Unattended-Upgrade \\\"1\\\";\" | sudo tee /etc/apt/apt.conf.d/20auto-upgrades",
      scriptCode: `# Rule: Enable Automatic Security Updates
echo "[-] Installing and enabling unattended-upgrades..."
if command -v apt-get &> /dev/null; then
    apt-get install -y unattended-upgrades &> /dev/null
    echo -e "APT::Periodic::Update-Package-Lists \\"1\\";\\nAPT::Periodic::Unattended-Upgrade \\"1\\";" > /etc/apt/apt.conf.d/20auto-upgrades
    echo "[+] Automatic updates enabled."
else
    echo "[!] apt-get not found. Skipping unattended upgrades setup."
fi`
    },
    {
      id: "lin-disable-fs",
      title: "Disable Unused Filesystems Modules",
      category: "System",
      severity: "low",
      description: "Configures modprobe to block unused file systems like freevxfs, jffs2, cramfs, and hfs.",
      rationale: "Blocking unused legacy kernel driver modules decreases the attack surface. It stops attackers from mounting foreign filesystems containing local privilege escalation payloads.",
      verification: "lsmod | grep -E \"cramfs|freevxfs|jffs2|hfs\"",
      remediation: "echo -e \"install cramfs /bin/true\\ninstall freevxfs /bin/true\\ninstall jffs2 /bin/true\\ninstall hfs /bin/true\" | sudo tee /etc/modprobe.d/unused-fs.conf",
      scriptCode: `# Rule: Disable Unused Filesystems
echo "[-] Blocking legacy filesystem modules in modprobe..."
cat << 'EOF' > /etc/modprobe.d/unused-fs.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
echo "[+] Unused filesystems disabled."`
    },
    {
      id: "lin-perms-shadow",
      title: "Secure Permissions on Shadow & Passwd Files",
      category: "Permissions",
      severity: "high",
      description: "Applies tight read/write user-permissions to critical account databases.",
      rationale: "/etc/shadow contains salted password hashes. Allowing standard users read permissions facilitates local password cracking. Restricting permissions to root-only protects secret credentials.",
      verification: "stat -c \"%a %U %G\" /etc/shadow /etc/passwd",
      remediation: "sudo chmod 644 /etc/passwd /etc/group && sudo chmod 600 /etc/shadow /etc/gshadow && sudo chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow",
      scriptCode: `# Rule: Secure Permissions on /etc/passwd and /etc/shadow
echo "[-] Applying secure user privileges to authentication databases..."
chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow
chmod 644 /etc/passwd /etc/group
chmod 600 /etc/shadow /etc/gshadow
echo "[+] File permissions updated."`
    },
    {
      id: "lin-sysctl",
      title: "Disable IP Forwarding & Enable SYN Cookies",
      category: "Network",
      severity: "medium",
      description: "Restricts IPv4 traffic forwarding and enables TCP SYN Flood defense in sysctl.",
      rationale: "IP forwarding makes the machine act like a router/bridge, exposing other subnets. SYN cookies dynamically mitigate TCP connection saturation (SYN Floods).",
      verification: "sysctl net.ipv4.ip_forward net.ipv4.tcp_syncookies",
      remediation: "echo -e \"net.ipv4.ip_forward = 0\\nnet.ipv4.tcp_syncookies = 1\" | sudo tee -a /etc/sysctl.conf && sudo sysctl -p",
      scriptCode: `# Rule: Sysctl Network Hardening
echo "[-] Hardening network kernel parameters in sysctl..."
backup_file "/etc/sysctl.conf"
cat << 'EOF' >> /etc/sysctl.conf
# OS Hardening configuration
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
sysctl -p &> /dev/null
echo "[+] Sysctl parameters reloaded successfully."`
    },
    {
      id: "lin-auditd",
      title: "Enable Auditing Daemon (auditd)",
      category: "Auditing",
      severity: "medium",
      description: "Installs and enables the kernel audit logging utility.",
      rationale: "The 'auditd' daemon logs system calls, file integrity alerts, and socket activities. This creates a tamper-proof audit trail for forensic post-incident analyses.",
      verification: "systemctl is-active auditd",
      remediation: "sudo apt-get install -y auditd && sudo systemctl enable --now auditd",
      scriptCode: `# Rule: Install and Enable auditd
echo "[-] Installing and starting auditd system daemon..."
if command -v apt-get &> /dev/null; then
    apt-get install -y auditd &> /dev/null
    systemctl enable auditd &> /dev/null
    systemctl start auditd &> /dev/null
    echo "[+] auditd system auditing is active."
else
    echo "[!] apt-get not found. Skipping auditd installation."
fi`
    }
  ]
};

// Global App State
const state = {
  selectedPlatform: "windows",
  checklistState: {}, // { id: checkedBoolean }
  scriptInclusions: {}, // { id: includedBoolean }
  expandedRuleId: null,
  searchTerm: "",
  activeCategoryFilter: "all"
};

// DOM Elements cache
let elements = {};

// Initialize application state
function init() {
  cacheDOMElements();
  loadStateFromStorage();
  bindEvents();
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
    toast: document.getElementById("toast")
  };
}

function loadStateFromStorage() {
  // Load local storage if exists
  const storedChecklist = localStorage.getItem("os_hardening_checklist");
  const storedScriptInclusions = localStorage.getItem("os_hardening_inclusions");
  const storedPlatform = localStorage.getItem("os_hardening_platform");
  
  if (storedPlatform) {
    state.selectedPlatform = storedPlatform;
  }
  
  // Initialize checklist & script default inclusion state
  const rules = HARDENING_RULES[state.selectedPlatform];
  rules.forEach(rule => {
    state.checklistState[rule.id] = false;
    state.scriptInclusions[rule.id] = true;
  });

  if (storedChecklist) {
    try {
      const parsed = JSON.parse(storedChecklist);
      Object.assign(state.checklistState, parsed);
    } catch (e) {
      console.error("Failed to parse checklist state", e);
    }
  }

  if (storedScriptInclusions) {
    try {
      const parsed = JSON.parse(storedScriptInclusions);
      Object.assign(state.scriptInclusions, parsed);
    } catch (e) {
      console.error("Failed to parse script inclusions state", e);
    }
  }
}

function saveStateToStorage() {
  localStorage.setItem("os_hardening_checklist", JSON.stringify(state.checklistState));
  localStorage.setItem("os_hardening_inclusions", JSON.stringify(state.scriptInclusions));
  localStorage.setItem("os_hardening_platform", state.selectedPlatform);
}

function bindEvents() {
  // Platform switching
  elements.platformTabs.addEventListener("click", (e) => {
    const btn = e.target.closest(".platform-btn");
    if (!btn || btn.classList.contains("active")) return;
    
    // Switch active platform tab style
    elements.platformTabs.querySelectorAll(".platform-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    
    state.selectedPlatform = btn.dataset.platform;
    state.expandedRuleId = null;
    state.activeCategoryFilter = "all";
    
    // Re-initialize default script settings for newly selected platform rules
    HARDENING_RULES[state.selectedPlatform].forEach(rule => {
      if (state.checklistState[rule.id] === undefined) {
        state.checklistState[rule.id] = false;
      }
      if (state.scriptInclusions[rule.id] === undefined) {
        state.scriptInclusions[rule.id] = true;
      }
    });

    saveStateToStorage();
    renderFilters();
    renderChecklist();
    updateDashboard();
    generateScriptPreview();
  });

  // Search input event
  elements.searchBox.addEventListener("input", (e) => {
    state.searchTerm = e.target.value.toLowerCase();
    renderChecklist();
  });

  // Category filter clicks
  elements.filterGroup.addEventListener("click", (e) => {
    const btn = e.target.closest(".filter-btn");
    if (!btn) return;
    
    elements.filterGroup.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    
    state.activeCategoryFilter = btn.dataset.category;
    renderChecklist();
  });

  // Bulk Actions
  elements.toggleAllCheckboxesBtn.addEventListener("click", () => {
    const currentRules = getFilteredRules();
    if (currentRules.length === 0) return;
    
    // Check if any rule in the current selection is unchecked
    const hasUnchecked = currentRules.some(r => !state.checklistState[r.id]);
    currentRules.forEach(r => {
      state.checklistState[r.id] = hasUnchecked;
    });
    
    saveStateToStorage();
    renderChecklist();
    updateDashboard();
  });

  elements.toggleAllScriptBtn.addEventListener("click", () => {
    const currentRules = getFilteredRules();
    if (currentRules.length === 0) return;
    
    const hasExcluded = currentRules.some(r => !state.scriptInclusions[r.id]);
    currentRules.forEach(r => {
      state.scriptInclusions[r.id] = hasExcluded;
    });
    
    saveStateToStorage();
    renderChecklist();
    generateScriptPreview();
  });

  // Copy to Clipboard Action
  elements.copyBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(elements.codeViewer.value).then(() => {
      showToast("Script copied to clipboard!");
    }).catch(err => {
      showToast("Failed to copy code: " + err, true);
    });
  });

  // Download Script Action
  elements.downloadBtn.addEventListener("click", () => {
    const scriptContent = elements.codeViewer.value;
    const isWin = state.selectedPlatform === "windows";
    const filename = isWin ? "win-hardening.ps1" : "linux-hardening.sh";
    const mime = isWin ? "text/plain" : "application/x-sh";
    
    const blob = new Blob([scriptContent], { type: mime });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast("Script download started!");
  });
}

function getFilteredRules() {
  const allRules = HARDENING_RULES[state.selectedPlatform];
  return allRules.filter(rule => {
    const matchesSearch = rule.title.toLowerCase().includes(state.searchTerm) || 
                          rule.description.toLowerCase().includes(state.searchTerm) ||
                          rule.rationale.toLowerCase().includes(state.searchTerm);
    const matchesCategory = state.activeCategoryFilter === "all" || rule.category === state.activeCategoryFilter;
    return matchesSearch && matchesCategory;
  });
}

// Generate the distinct categories in the toolbar
function renderFilters() {
  const allRules = HARDENING_RULES[state.selectedPlatform];
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

// Main list render
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
    const isChecked = state.checklistState[rule.id] || false;
    const isIncluded = state.scriptInclusions[rule.id] !== false;
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

// Event functions triggered from html attributes or handlers
window.toggleCheck = function(id, event) {
  event.stopPropagation(); // Avoid expanding card when ticking checkbox
  state.checklistState[id] = !state.checklistState[id];
  saveStateToStorage();
  
  // Find card and toggle class directly for responsiveness
  const card = document.querySelector(`.checklist-item[data-id="${id}"]`);
  if (card) {
    if (state.checklistState[id]) {
      card.classList.add("checked");
    } else {
      card.classList.remove("checked");
    }
  }
  updateDashboard();
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

window.toggleScriptInclusion = function(id, checked) {
  state.scriptInclusions[id] = checked;
  saveStateToStorage();
  generateScriptPreview();
};

function updateDashboard() {
  const allRules = HARDENING_RULES[state.selectedPlatform];
  const total = allRules.length;
  
  let completed = 0;
  allRules.forEach(r => {
    if (state.checklistState[r.id]) completed++;
  });
  
  const pending = total - completed;
  const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;
  
  elements.progressValue.textContent = `${percentage}%`;
  elements.completedValue.textContent = completed;
  elements.pendingValue.textContent = pending;
}

function generateScriptPreview() {
  const isWin = state.selectedPlatform === "windows";
  elements.fileName.textContent = isWin ? "win-hardening.ps1" : "linux-hardening.sh";
  
  const selectedRules = HARDENING_RULES[state.selectedPlatform].filter(r => state.scriptInclusions[r.id] !== false);
  
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
  elements.toast.textContent = message;
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

// Initialise on load
document.addEventListener("DOMContentLoaded", () => {
  init();
  renderFilters();
});
