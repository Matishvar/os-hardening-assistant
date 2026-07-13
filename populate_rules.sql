-- OS Hardening Rules database seeds
-- Windows Rules
INSERT OR REPLACE INTO hardening_app_hardeningrule (id, platform, title, category, severity, description, rationale, verification, remediation, script_code) VALUES
('win-guest-acct', 'windows', 'Disable Guest Account', 'Accounts', 'high', 'Disables the built-in Guest account to restrict unauthorized access.', 'Active guest accounts provide an open gateway for malicious network users or local threat actors to log in anonymously without credentials.', 'Get-LocalUser -Name Guest | Select-Object Name, Enabled', 'Open "Computer Management" (press Win+X). Go to System Tools -> Local Users and Groups -> Users. Double-click "Guest", check "Account is disabled", and click OK.', '# Rule: Disable built-in Guest account
Write-Host "[-] Disabling built-in Guest account..." -ForegroundColor Gray
try {
    Disable-LocalUser -Name "Guest" -ErrorAction Stop
    Write-Host "[+] Guest account disabled successfully." -ForegroundColor Green
} catch {
    Write-Warning "Failed to disable Guest account: $_"
}'),

('win-pw-length', 'windows', 'Enforce Minimum Password Length (14 chars)', 'Password Policy', 'high', 'Configures the minimum required password length to 14 characters.', 'Short passwords are highly vulnerable to local/offline cryptographic dictionary attacks. Enforcing a length of 14 or more characters significantly increases search-space complexity.', 'net accounts', 'Search for "Local Security Policy" in Start menu. Expand Account Policies -> Password Policy. Double-click "Minimum password length", set to 14, and click OK.', '# Rule: Enforce minimum password length to 14
Write-Host "[-] Configuring minimum password length to 14..." -ForegroundColor Gray
try {
    net accounts /minpwlen:14
    Write-Host "[+] Password length requirement enforced." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set password length: $_"
}'),

('win-defender-rt', 'windows', 'Enable Windows Defender Real-Time Protection', 'Antivirus', 'critical', 'Ensures Microsoft Defender Antivirus actively scans for malware and threats in real-time.', 'Real-time monitoring detects and blocks threats during execution, file creation, or download before they can compromise the system.', 'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled', 'Open Windows Settings -> Privacy & Security -> Windows Security -> Virus & threat protection. Click "Manage settings" and toggle "Real-time protection" to ON.', '# Rule: Enable Microsoft Defender Real-Time Protection
Write-Host "[-] Enabling Microsoft Defender Real-Time Protection..." -ForegroundColor Gray
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Write-Host "[+] Defender Real-Time Protection enabled." -ForegroundColor Green
} catch {
    Write-Warning "Failed to enable Defender Real-Time Protection: $_"
}'),

('win-firewall-profiles', 'windows', 'Enable Firewall & Block Default Inbound', 'Network', 'high', 'Enables Windows Defender Firewall on all profiles (Domain, Private, Public) and sets default incoming behavior to Block.', 'A running host-based firewall is a primary defense line. Default-blocking all incoming traffic ensures that only explicitly whitelisted services are reachable from outside.', 'Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction', 'Open Windows Settings -> Privacy & Security -> Windows Security -> Firewall & network protection. Select Domain, Private, and Public profiles individually and toggle them to ON.', '# Rule: Enable Firewall and set Default Inbound to Block
Write-Host "[-] Configuring Windows Firewall profiles..." -ForegroundColor Gray
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -ErrorAction Stop
    Write-Host "[+] Windows Firewall enabled and inbound traffic blocked by default." -ForegroundColor Green
} catch {
    Write-Warning "Failed to configure Windows Firewall: $_"
}'),

('win-disable-llmnr', 'windows', 'Disable LLMNR (Link-Local Multicast Name Resolution)', 'Network', 'high', 'Turns off LLMNR to prevent local multicast spoofing attacks.', 'LLMNR allows hosts on the same subnet to resolve names without DNS. Attackers can listen for these broadcasts and spoof target names to intercept network hashes and passwords.', 'Get-ItemProperty -Path ''HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'' -Name ''EnableMulticast'' -ErrorAction SilentlyContinue', 'Open Group Policy Editor (Win+R -> gpedit.msc). Navigate to Computer Configuration -> Administrative Templates -> Network -> DNS Client. Enable "Turn off Link-Local Multicast Name Resolution".', '# Rule: Disable LLMNR via Registry
Write-Host "[-] Disabling LLMNR (Link-Local Multicast Name Resolution)..." -ForegroundColor Gray
try {
    $registryPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $registryPath)) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
    }
    New-ItemProperty -Path $registryPath -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    Write-Host "[+] LLMNR disabled successfully." -ForegroundColor Green
} catch {
    Write-Warning "Failed to disable LLMNR: $_"
}'),

('win-smbv1', 'windows', 'Disable SMBv1 & Enforce SMBv3 Security', 'Services', 'critical', 'Disables the obsolete and insecure SMBv1 protocol, while enabling and enforcing SMBv3 transport encryption and packet signing.', 'SMBv1 is vulnerable to severe exploits like EternalBlue. SMBv3 introduces major security capabilities including transport-level data encryption and cryptographic signing, preventing man-in-the-middle attacks and data sniffing.', 'Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EncryptData, RequireSecuritySignature', 'Search for "Turn Windows features on or off" in Start menu. Uncheck "SMB 1.0/CIFS File Sharing Support" and reboot. Enforce SMBv3 transport encryption by running: Set-SmbServerConfiguration -EncryptData $true -Force', '# Rule: Disable SMBv1 and Enforce SMBv3 Security
Write-Host "[-] Configuring secure SMB settings (Disabling SMBv1, Enforcing SMBv3)..." -ForegroundColor Gray
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction SilentlyContinue
    Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction SilentlyContinue
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
    Write-Host "[+] SMBv1 disabled and SMBv3 encryption/signing enforced successfully." -ForegroundColor Green
} catch {
    Write-Warning "Failed to secure SMB configuration: $_"
}'),

('win-uac-always', 'windows', 'Set UAC to ''Always Notify''', 'System', 'high', 'Raises User Account Control (UAC) prompts to the maximum level to prevent unauthorized administrator actions.', 'With UAC set to ''Always Notify'', any administrative change requires explicit manual consent. This prevents background scripts or malwares from silently escalating privileges.', 'Get-ItemProperty -Path ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'' -Name ''ConsentPromptBehaviorAdmin''', 'Search for "Change User Account Control settings" in Start menu. Move the slider up to "Always notify me", and click OK.', '# Rule: Set UAC to ''Always Notify''
Write-Host "[-] Setting User Account Control (UAC) to Always Notify..." -ForegroundColor Gray
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -ErrorAction Stop
    Write-Host "[+] UAC set to Always Notify on Secure Desktop." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set UAC settings: $_"
}'),

('win-powershell-policy', 'windows', 'Set PowerShell Execution Policy to RemoteSigned', 'System', 'medium', 'Restricts script execution so that downloaded scripts must be signed by a trusted publisher before running.', 'Defaulting execution policy to RemoteSigned prevents standard users from easily double-clicking and executing arbitrary untrusted scripts from the internet.', 'Get-ExecutionPolicy', 'Open PowerShell as Administrator and run: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force', '# Rule: Restrict PowerShell Execution Policy to RemoteSigned
Write-Host "[-] Restricting PowerShell Execution Policy to RemoteSigned..." -ForegroundColor Gray
try {
    Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
    Write-Host "[+] Execution Policy successfully set to RemoteSigned." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set Execution Policy: $_"
}'),

('win-audit-logon', 'windows', 'Enable Auditing for Logon Failures', 'Auditing', 'medium', 'Enables event log recording for failed logon attempts.', 'Audit logs are critical for security monitoring. Logging logon failures allows detection of brute-force campaigns, credential harvesting, or unauthorized local logins.', 'auditpol /get /subcategory:''Logon''', 'Open Command Prompt as Administrator and run: auditpol /set /subcategory="Logon" /failure:enable', '# Rule: Enable Auditing for Logon Failures
Write-Host "[-] Configuring Audit Policy for Logon Failures..." -ForegroundColor Gray
try {
    auditpol /set /subcategory:"Logon" /failure:enable
    Write-Host "[+] Auditing for Logon Failures enabled successfully." -ForegroundColor Green
} catch {
    Write-Warning "Failed to enable logon failure auditing: $_"
}'),

('win-autorun', 'windows', 'Disable AutoPlay / AutoRun for all drives', 'System', 'medium', 'Disables AutoPlay features on all drives to block automatic malware launch from USB/removable drives.', 'Removable USB media can host malicious autorun scripts. Disabling NoDriveTypeAutoRun blocks programs from launching automatically when USB media is connected.', 'Get-ItemProperty -Path ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'' -Name ''NoDriveTypeAutoRun''', 'Open Registry Editor. Navigate to HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer. Create a DWORD named "NoDriveTypeAutoRun" and set its value to 255 (decimal).', '# Rule: Disable AutoRun/AutoPlay for all drives
Write-Host "[-] Disabling AutoPlay for all drives..." -ForegroundColor Gray
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (-not (Test-Path $regPath)) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 255 -Force -ErrorAction Stop
    Write-Host "[+] AutoPlay disabled for all drive types." -ForegroundColor Green
} catch {
    Write-Warning "Failed to disable AutoPlay: $_"
}'),

('win-restrict-local-network', 'windows', 'Restrict Local Accounts Network Access', 'Accounts', 'high', 'Prevents unprivileged local accounts from being utilized for remote network operations.', 'Restricting blank password network operations prevents lateral movement in network environments by restricting local credentials to console logs only.', 'Get-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'' -Name ''LimitBlankPasswordUse''', 'Search for "Local Security Policy". Expand Local Policies -> Security Options. Double-click "Accounts: Limit local account use of blank passwords to console logon only", and select Enabled.', '# Rule: Limit Blank Password Remote Use
Write-Host "[-] Restricting blank password network usage..." -ForegroundColor Gray
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Force -ErrorAction Stop
    Write-Host "[+] Local accounts network blank password usage restricted." -ForegroundColor Green
} catch {
    Write-Warning "Failed to restrict network accounts: $_"
}');

-- Linux Rules
INSERT OR REPLACE INTO hardening_app_hardeningrule (id, platform, title, category, severity, description, rationale, verification, remediation, script_code) VALUES
('lin-ssh-root', 'linux', 'Disable Root Login over SSH', 'Accounts', 'critical', 'Restricts direct root user access over SSH connection.', 'The ''root'' user is a universal administrator name across all Linux hosts. Disabling direct root login forces attackers to discover both a customized username and password/key first, preventing direct administrative brute force.', 'grep -i "^PermitRootLogin" /etc/ssh/sshd_config', 'Open terminal and edit /etc/ssh/sshd_config. Set "PermitRootLogin no". Save, and run: sudo systemctl restart sshd', '# Rule: Disable Root Login over SSH
echo "[-] Disabling direct root login over SSH..."
if [ -f /etc/ssh/sshd_config ]; then
    backup_file "/etc/ssh/sshd_config"
    sed -i ''s/^#\?PermitRootLogin.*/PermitRootLogin no/g'' /etc/ssh/sshd_config
    systemctl restart sshd || systemctl restart ssh
    echo "[+] Root SSH login disabled."
else
    echo "[!] sshd_config not found. Skipping SSH config."
fi'),

('lin-ssh-key', 'linux', 'Enforce SSH Key-Based Authentication Only', 'Accounts', 'high', 'Disables standard password authentication for SSH logins.', 'Passwords are subject to credential stuffing and brute-force attacks. Enforcing keys ensures that only accounts possessing the cryptographic private key can authenticate.', 'grep -i "^PasswordAuthentication" /etc/ssh/sshd_config', 'Open terminal and edit /etc/ssh/sshd_config. Set "PasswordAuthentication no". Save, and run: sudo systemctl restart sshd', '# Rule: Enforce SSH Key-Based Authentication
echo "[-] Disabling SSH password authentication..."
if [ -f /etc/ssh/sshd_config ]; then
    backup_file "/etc/ssh/sshd_config"
    sed -i ''s/^#\?PasswordAuthentication.*/PasswordAuthentication no/g'' /etc/ssh/sshd_config
    systemctl restart sshd || systemctl restart ssh
    echo "[+] Password-based SSH logins disabled."
else
    echo "[!] sshd_config not found. Skipping."
fi'),

('lin-ufw-setup', 'linux', 'Configure UFW Firewall Default Policies', 'Network', 'high', 'Installs UFW (if missing) and sets policy to deny incoming and allow outgoing traffic.', 'Default incoming deny posture blocks port scans and unauthorized access to running listening processes. Permitting outgoing traffic allows updates and downloads to continue.', 'sudo ufw status verbose', 'Open terminal. Run: sudo apt install ufw; sudo ufw default deny incoming; sudo ufw default allow outgoing; sudo ufw allow 22/tcp; sudo ufw enable', '# Rule: Configure UFW Firewall Policies
echo "[-] Installing and configuring UFW Firewall..."
if command -v apt-get &> /dev/null; then
    apt-get update -y &> /dev/null
    apt-get install -y ufw &> /dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw --force enable
    echo "[+] UFW configured (default deny incoming, SSH allowed)."
else
    echo "[!] apt-get not found. Cannot configure UFW automatically."
fi'),

('lin-secure-shm', 'linux', 'Secure Shared Memory (/dev/shm)', 'System', 'medium', 'Mounts /dev/shm with ''noexec, nosuid, nodev'' flags to prevent malicious script executions.', '/dev/shm is a shared memory region that acts as a fast temporary drive. Malicious users often write exploits to /dev/shm. Restricting mount flags stops binary executions inside this partition.', 'mount | grep /dev/shm', 'Open terminal. Append: "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" to /etc/fstab, then run: sudo mount -o remount /dev/shm', '# Rule: Secure Shared Memory (/dev/shm)
echo "[-] Securing shared memory partition (/dev/shm)..."
if ! grep -q "/dev/shm" /etc/fstab; then
    backup_file "/etc/fstab"
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    mount -o remount /dev/shm &> /dev/null || mount /dev/shm
    echo "[+] Secured shared memory (/dev/shm) in /etc/fstab."
else
    echo "[!] /dev/shm already defined in /etc/fstab."
fi'),

('lin-auto-upgrades', 'linux', 'Enable Automatic Security Updates', 'System', 'high', 'Enables ''unattended-upgrades'' to automatically patch security vulnerabilities.', 'Keeping packages patched is critical. Outdated dependencies leave systems open to known public CVEs. Auto-upgrades apply safety patches as soon as they release.', 'cat /etc/apt/apt.conf.d/20auto-upgrades', 'Open terminal. Run: sudo apt install unattended-upgrades. Configure /etc/apt/apt.conf.d/20auto-upgrades to enable auto-update lists and unattended-upgrade.', '# Rule: Enable Automatic Security Updates
echo "[-] Installing and enabling unattended-upgrades..."
if command -v apt-get &> /dev/null; then
    apt-get install -y unattended-upgrades &> /dev/null
    echo -e "APT::Periodic::Update-Package-Lists \\"1\\";\\nAPT::Periodic::Unattended-Upgrade \\"1\\";" > /etc/apt/apt.conf.d/20auto-upgrades
    echo "[+] Automatic updates enabled."
else
    echo "[!] apt-get not found. Skipping unattended upgrades setup."
fi'),

('lin-disable-fs', 'linux', 'Disable Unused Filesystems Modules', 'System', 'low', 'Configures modprobe to block unused file systems like freevxfs, jffs2, cramfs, and hfs.', 'Blocking unused legacy kernel driver modules decreases the attack surface. It stops attackers from mounting foreign filesystems containing local privilege escalation payloads.', 'lsmod | grep -E "cramfs|freevxfs|jffs2|hfs"', 'Open terminal. Create file /etc/modprobe.d/unused-fs.conf, add: "install <fs_name> /bin/true" for cramfs, freevxfs, jffs2, and hfs.', '# Rule: Disable Unused Filesystems
echo "[-] Blocking legacy filesystem modules in modprobe..."
cat << ''EOF'' > /etc/modprobe.d/unused-fs.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
echo "[+] Unused filesystems disabled."'),

('lin-perms-shadow', 'linux', 'Secure Permissions on Shadow & Passwd Files', 'Permissions', 'high', 'Applies tight read/write user-permissions to critical account databases.', '/etc/shadow contains salted password hashes. Allowing standard users read permissions facilitates local password cracking. Restricting permissions to root-only protects secret credentials.', 'stat -c "%a %U %G" /etc/shadow /etc/passwd', 'Open terminal. Run: sudo chown root:root /etc/passwd /etc/shadow; sudo chmod 644 /etc/passwd; sudo chmod 600 /etc/shadow', '# Rule: Secure Permissions on /etc/passwd and /etc/shadow
echo "[-] Applying secure user privileges to authentication databases..."
chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow
chmod 644 /etc/passwd /etc/group
chmod 600 /etc/shadow /etc/gshadow
echo "[+] File permissions updated."'),

('lin-sysctl', 'linux', 'Disable IP Forwarding & Enable SYN Cookies', 'Network', 'medium', 'Restricts IPv4 traffic forwarding and enables TCP SYN Flood defense in sysctl.', 'IP forwarding makes the machine act like a router/bridge, exposing other subnets. SYN cookies dynamically mitigate TCP connection saturation (SYN Floods).', 'sysctl net.ipv4.ip_forward net.ipv4.tcp_syncookies', 'Open terminal. Append: "net.ipv4.ip_forward = 0" and "net.ipv4.tcp_syncookies = 1" to /etc/sysctl.conf, then run: sudo sysctl -p', '# Rule: Sysctl Network Hardening
echo "[-] Hardening network kernel parameters in sysctl..."
backup_file "/etc/sysctl.conf"
cat << ''EOF'' >> /etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
sysctl -p &> /dev/null
echo "[+] Sysctl parameters reloaded successfully."'),

('lin-auditd', 'linux', 'Enable Auditing Daemon (auditd)', 'Auditing', 'medium', 'Installs and enables the kernel audit logging utility.', 'The ''auditd'' daemon logs system calls, file integrity alerts, and socket activities. This creates a tamper-proof audit trail for forensic post-incident analyses.', 'systemctl is-active auditd', 'Open terminal. Run: sudo apt install auditd; sudo systemctl enable --now auditd', '# Rule: Install and Enable auditd
echo "[-] Installing and starting auditd system daemon..."
if command -v apt-get &> /dev/null; then
    apt-get install -y auditd &> /dev/null
    systemctl enable auditd &> /dev/null
    systemctl start auditd &> /dev/null
    echo "[+] auditd system auditing is active."
else
    echo "[!] apt-get not found. Skipping auditd installation."
fi'),

('lin-disable-usb-storage', 'linux', 'Disable USB Storage Kernel Driver', 'System', 'high', 'Blocks loading of the usb-storage driver to prevent unauthorized USB device access.', 'Disabling loading of usb-storage module prevents attackers from plugging in hardware keys or external devices to extract directory tables.', 'cat /etc/modprobe.d/blacklist-usb.conf', 'Open terminal. Run: echo "blacklist usb-storage" | sudo tee /etc/modprobe.d/blacklist-usb.conf', '# Rule: Blacklist USB Storage Kernel Module
echo "[-] Blacklisting usb-storage driver module..."
echo "blacklist usb-storage" > /etc/modprobe.d/blacklist-usb.conf
echo "[+] USB storage blacklisted."'),

('lin-dmesg-restrict', 'linux', 'Restrict Kernel Log Access (dmesg)', 'System', 'medium', 'Enforces dmesg_restrict to allow only administrators to view kernel logs.', 'Restricting dmesg log access blocks unprivileged local users from reading kernel addresses that facilitate local privilege exploits.', 'sysctl kernel.dmesg_restrict', 'Open terminal. Append "kernel.dmesg_restrict = 1" to /etc/sysctl.conf and run: sudo sysctl -p', '# Rule: Restrict dmesg log access
echo "[-] Securing kernel logging access..."
backup_file "/etc/sysctl.conf"
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf
sysctl -p &> /dev/null
echo "[+] kernel dmesg access restricted."');
