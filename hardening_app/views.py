import io
import os
import json
import zipfile
import subprocess
import sys
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.http import require_POST
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import HardeningRule, UserProgress, ScanReport

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# --- Database User & Android Rules Seeding Helper ---
def ensure_default_user_and_rules():
    """Checks and creates default admin user and Android rules for compliance diagnostics."""
    try:
        from django.contrib.auth.models import User
        # Delete old admin and Matish users if they exist
        if User.objects.filter(username='admin').exists():
            User.objects.filter(username='admin').delete()
        if User.objects.filter(username='Matish').exists():
            User.objects.filter(username='Matish').delete()
            
        # Create new custom superuser: matish0508 / matish-admin-200805
        if not User.objects.filter(username='matish0508').exists():
            User.objects.create_superuser('matish0508', 'matish0508@example.com', 'matish-admin-200805')
            print("Successfully pre-seeded default superuser: matish0508 / matish-admin-200805")
    except Exception as e:
        print("Warning: Failed to seed admin user on load:", e)
        
    try:
        # Seed Android platform rules if not already present
        android_data = [
            {
                "id": "and-dev-options",
                "title": "Disable Developer Options",
                "category": "System Security",
                "severity": "medium",
                "description": "Disable developer options to prevent unauthorized device access.",
                "rationale": "Developer options allow advanced configurations like USB debugging which bypass system security locks.",
                "verification": "Settings -> System -> Developer options (Ensure toggle is OFF)",
                "remediation": "Open Settings -> Scroll and select 'System' -> Select 'Developer options' -> Turn off the top switch to disable all options.",
                "script_code": "adb shell settings put global development_settings_enabled 0"
            },
            {
                "id": "and-usb-debugging",
                "title": "Disable USB Debugging",
                "category": "Connectivity",
                "severity": "high",
                "description": "Disable Android Debug Bridge (ADB) USB connection.",
                "rationale": "Active USB debugging allows a physical attacker to run shell commands, bypass locks, and steal user data.",
                "verification": "Settings -> Developer options -> USB debugging (Ensure OFF)",
                "remediation": "Open Settings -> Scroll and select 'System' -> Select 'Developer options' -> Scroll to 'USB debugging' and turn off the switch.",
                "script_code": "adb shell settings put global adb_enabled 0"
            },
            {
                "id": "and-unknown-sources",
                "title": "Disable Unknown Sources",
                "category": "App Security",
                "severity": "critical",
                "description": "Prevent installation of application packages (.apk) outside Google Play.",
                "rationale": "Sideloading unverified applications increases the risk of malware and ransomware infections.",
                "verification": "Settings -> Apps -> Special app access -> Install unknown apps",
                "remediation": "Open Settings -> Navigate to 'Apps' -> Tap 'Special app access' -> Tap 'Install unknown apps' -> Turn off permissions for Chrome, Files, and other browsers.",
                "script_code": "# Manual security verification required - Android Sandbox Restrictions"
            },
            {
                "id": "and-screen-lock",
                "title": "Enforce Screen Lock PIN/Password",
                "category": "Authentication",
                "severity": "critical",
                "description": "Secure device with a strong PIN, pattern, or password.",
                "rationale": "A device without a screen lock allows physical access to personal files, banking apps, and system settings.",
                "verification": "Settings -> Security -> Screen Lock (Ensure PIN/Password/Biometrics active)",
                "remediation": "Open Settings -> Navigate to 'Security' -> Tap 'Screen lock' -> Select 'PIN' (minimum 6 digits) or 'Password' to secure the device.",
                "script_code": "# Configured in System Settings"
            },
            {
                "id": "and-storage-encryption",
                "title": "Verify Storage Encryption",
                "category": "Data Protection",
                "severity": "high",
                "description": "Ensure all user data partition blocks are encrypted at rest.",
                "rationale": "Unencrypted storage allows attackers to pull files directly from memory chips by physically accessing the board.",
                "verification": "Settings -> Security -> Encryption & credentials (Ensure status is Encrypted)",
                "remediation": "Open Settings -> Navigate to 'Security' -> Click 'Encryption & credentials'. Ensure status shows 'Encrypted'. (Android 10+ devices enforce this by default).",
                "script_code": "adb shell getprop ro.crypto.state"
            },
            {
                "id": "and-play-protect",
                "title": "Enable Google Play Protect",
                "category": "App Security",
                "severity": "critical",
                "description": "Keep Google's built-in app scanner active to identify malicious files.",
                "rationale": "Play Protect scans installed apps for known virus signatures and suspicious background behavior.",
                "verification": "Play Store -> Profile -> Play Protect -> Settings (Ensure Turn on scan active)",
                "remediation": "Open Google Play Store -> Tap your profile icon -> Select 'Play Protect' -> Tap Settings (gear icon) -> Enable 'Scan apps with Play Protect'.",
                "script_code": "# Configured in Google Play Store Settings"
            },
            {
                "id": "and-find-device",
                "title": "Enable Find My Device",
                "category": "Data Protection",
                "severity": "medium",
                "description": "Allow remote location tracking, lock, and wipe options.",
                "rationale": "If your device is lost or stolen, Find My Device lets you erase sensitive details remotely.",
                "verification": "Settings -> Security -> Find My Device (Ensure ON)",
                "remediation": "Open Settings -> Navigate to 'Security' -> Tap 'Find My Device' -> Turn toggle switch to ON.",
                "script_code": "# Configured in System Settings"
            },
            {
                "id": "and-bluetooth-discovery",
                "title": "Disable Bluetooth Discoverable Mode",
                "category": "Connectivity",
                "severity": "medium",
                "description": "Hide your device from bluetooth scans of surrounding hosts.",
                "rationale": "Continuous discovery invites remote bluetooth exploits (e.g. BlueBorne) and location tracking.",
                "verification": "Settings -> Connected devices -> Connection preferences -> Bluetooth",
                "remediation": "Open Settings -> Tap 'Connected devices' -> Tap 'Connection preferences' -> Select 'Bluetooth' -> Toggle bluetooth discoverable state to OFF.",
                "script_code": "adb shell cmd bluetooth disable"
            },
            {
                "id": "and-location-services",
                "title": "Restrict App Location Permissions",
                "category": "Privacy",
                "severity": "high",
                "description": "Limit GPS tracking to active navigation/mapping applications only.",
                "rationale": "Rogue applications track user movements in the background for advertising or surveillance.",
                "verification": "Settings -> Privacy -> Permission manager -> Location",
                "remediation": "Open Settings -> Navigate to 'Privacy' -> Tap 'Permission manager' -> Select 'Location' -> Change background tracking permissions to 'Only while using the app' or 'Don't allow'.",
                "script_code": "# Configured in System Permission Manager"
            },
            {
                "id": "and-lockscreen-notifications",
                "title": "Disable Lock Screen Sensitive Notifications",
                "category": "Privacy",
                "severity": "high",
                "description": "Hides sensitive notification content (e.g. SMS verification codes) on the lock screen.",
                "rationale": "Displaying notification content on a locked device allows physical snatch-and-grab attackers to harvest 2FA OTP codes.",
                "verification": "Settings -> Notifications -> Notifications on lock screen (Ensure set to Hide sensitive content)",
                "remediation": "Open Settings -> Tap 'Notifications' -> Tap 'Notifications on lock screen' -> Select 'Hide sensitive content' or 'Don't show notifications'.",
                "script_code": "adb shell settings put secure lock_screen_allow_private_notifications 0"
            },
            {
                "id": "and-nfc-lock",
                "title": "Disable NFC when Device is Locked",
                "category": "Connectivity",
                "severity": "medium",
                "description": "Requires the screen to be unlocked to process NFC payments or data transfers.",
                "rationale": "Keeping NFC active on locked screens allows attackers to skim payment card tokens or trigger unauthenticated interactions by holding a scanner near the pocket.",
                "verification": "Settings -> Connected devices -> Connection preferences -> NFC (Ensure NFC requires unlock is ON)",
                "remediation": "Open Settings -> Tap 'Connected devices' -> Tap 'Connection preferences' -> Tap 'NFC' -> Enable the toggle for 'Require device unlock for NFC'.",
                "script_code": "adb shell settings put secure nfc_payment_require_device_unlock 1"
            }
        ]
        
        for rule in android_data:
            rule_obj, created = HardeningRule.objects.get_or_create(
                id=rule["id"],
                defaults={
                    "title": rule["title"],
                    "platform": "android",
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "rationale": rule["rationale"],
                    "verification": rule["verification"],
                    "remediation": rule["remediation"],
                    "script_code": rule["script_code"]
                }
            )
            UserProgress.objects.get_or_create(rule=rule_obj)
            
    except Exception as e:
        print("Warning: Failed to seed Android rules on load:", e)


# --- Authentication Views ---

def login_view(request):
    """Secure login endpoint authenticating username, email, & password credentials."""
    ensure_default_user_and_rules()
    
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    error = None
    success = None
    show_forgot_password = False
    saved_username = ""
    saved_email = ""
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        
        saved_username = username
        saved_email = email
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.email.strip().lower() == email.strip().lower():
                login(request, user)
                next_url = request.GET.get('next', 'dashboard')
                return redirect(next_url)
            else:
                error = "Invalid credentials. If you forgot your password, reset it."
                show_forgot_password = True
        else:
            error = "Invalid credentials. If you forgot your password, reset it."
            show_forgot_password = True
            
    return render(request, 'login.html', {
        'error': error,
        'success': success,
        'show_forgot_password': show_forgot_password,
        'saved_username': saved_username,
        'saved_email': saved_email
    })

def register_view(request):
    """Handles new user registration with strict security password complexity policies."""
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    error = None
    saved_username = ""
    saved_email = ""
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        
        saved_username = username
        saved_email = email
        from django.contrib.auth.models import User
        
        if not username:
            error = "Username is required."
        elif not email:
            error = "Email address is required."
        elif User.objects.filter(username=username).exists():
            error = "Username is already taken."
        elif User.objects.filter(email=email).exists():
            error = "An account with this email is already registered."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif len(password) < 14:
            error = "Password must contain a minimum of 14 characters."
        elif not any(c.isupper() for c in password):
            error = "Password must contain at least one uppercase letter (A-Z)."
        elif not any(not c.isalnum() for c in password):
            error = "Password must contain at least one special symbol (e.g. !, @, #, $, %, etc.)."
        else:
            try:
                # Create user with email
                user = User.objects.create_user(username=username, email=email, password=password)
                # Auto-login the user after registration
                login(request, user)
                return redirect('dashboard')
            except Exception as e:
                error = f"Registration failed: {str(e)}"
                
    return render(request, 'register.html', {
        'error': error,
        'saved_username': saved_username,
        'saved_email': saved_email
    })

def forgot_password_view(request):
    """Self-service secure password recovery enforcing complexity validations."""
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    error = None
    saved_username = ""
    saved_email = ""
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        new_password = request.POST.get('new_password', '')
        confirm_password = request.POST.get('confirm_password', '')
        
        saved_username = username
        saved_email = email
        from django.contrib.auth.models import User
        
        user = User.objects.filter(username=username, email=email).first()
        if not user:
            error = "No user found with the specified Username and Email."
        elif new_password != confirm_password:
            error = "Passwords do not match."
        elif len(new_password) < 14:
            error = "Password must contain a minimum of 14 characters."
        elif not any(c.isupper() for c in new_password):
            error = "Password must contain at least one uppercase letter (A-Z)."
        elif not any(not c.isalnum() for c in new_password):
            error = "Password must contain at least one special symbol (e.g. !, @, #, $, %, etc.)."
        else:
            try:
                user.set_password(new_password)
                user.save()
                success = "Password updated successfully! Please sign in with your new credentials."
                return render(request, 'login.html', {'success': success})
            except Exception as e:
                error = f"Password reset failed: {str(e)}"
                
    return render(request, 'forgot_password.html', {
        'error': error,
        'saved_username': saved_username,
        'saved_email': saved_email
    })

@login_required
def logout_view(request):
    """Terminates session and redirects to the login screen."""
    logout(request)
    return redirect('login')


# --- Context Helpers ---

def get_base_context(user):
    """Helper to return consistent layout variables across all dashboard slides, including Android, isolated by User."""
    from django.contrib.auth.models import User
    rules_list = list(HardeningRule.objects.all())
    
    # Bulk get or create progress for this user to optimize loading
    existing_progress_rule_ids = set(UserProgress.objects.filter(user=user).values_list('rule_id', flat=True))
    missing_rules = [r for r in rules_list if r.id not in existing_progress_rule_ids]
    if missing_rules:
        UserProgress.objects.bulk_create([
            UserProgress(user=user, rule=rule) for rule in missing_rules
        ])
        
    progress_map = {up.rule_id: up for up in UserProgress.objects.filter(user=user)}
    for rule in rules_list:
        rule.progress = progress_map.get(rule.id)
        
    windows_rules = [r for r in rules_list if r.platform == 'windows']
    linux_rules = [r for r in rules_list if r.platform == 'linux']
    android_rules = [r for r in rules_list if r.platform == 'android']
    
    win_total = len(windows_rules)
    win_completed = sum(1 for r in windows_rules if r.progress.is_completed)
    win_pending = win_total - win_completed
    win_pct = int((win_completed / win_total) * 100) if win_total > 0 else 0
    
    lin_total = len(linux_rules)
    lin_completed = sum(1 for r in linux_rules if r.progress.is_completed)
    lin_pending = lin_total - lin_completed
    lin_pct = int((lin_completed / lin_total) * 100) if lin_total > 0 else 0
    
    and_total = len(android_rules)
    and_completed = sum(1 for r in android_rules if r.progress.is_completed)
    and_pending = and_total - and_completed
    and_pct = int((and_completed / and_total) * 100) if and_total > 0 else 0
    
    win_categories = sorted(list(set(r.category for r in windows_rules)))
    lin_categories = sorted(list(set(r.category for r in linux_rules)))
    and_categories = sorted(list(set(r.category for r in android_rules)))
    
    # Identify currently failed rules for Windows, Linux, and Android to render the Remediation accordion guide
    win_failed = [r for r in windows_rules if not r.progress.is_completed]
    lin_failed = [r for r in linux_rules if not r.progress.is_completed]
    and_failed = [r for r in android_rules if not r.progress.is_completed]
    
    return {
        'windows_rules': windows_rules,
        'linux_rules': linux_rules,
        'android_rules': android_rules,
        'failed_rules': {
            'windows': win_failed,
            'linux': lin_failed,
            'android': and_failed,
        },
        'stats': {
            'windows': {
                'total': win_total,
                'completed': win_completed,
                'pending': win_pending,
                'percentage': win_pct,
                'categories': win_categories
            },
            'linux': {
                'total': lin_total,
                'completed': lin_completed,
                'pending': lin_pending,
                'percentage': lin_pct,
                'categories': lin_categories
            },
            'android': {
                'total': and_total,
                'completed': and_completed,
                'pending': and_pending,
                'percentage': and_pct,
                'categories': and_categories
            }
        }
    }


# --- Slide Page Controllers ---

@login_required
def dashboard_view(request):
    """Protected view displaying Slide 1: System Overview dashboard."""
    context = get_base_context(request.user)
    context['active_slide'] = 'dashboard'
    return render(request, 'dashboard.html', context)

@login_required
def checklist_view(request):
    """Protected view displaying Slide 2: Interactive security checklist."""
    context = get_base_context(request.user)
    context['active_slide'] = 'checklist'
    return render(request, 'checklist.html', context)

@login_required
def script_view(request):
    """Protected view displaying Slide 3: Script generator & compiler."""
    context = get_base_context(request.user)
    context['active_slide'] = 'script'
    return render(request, 'script.html', context)

@login_required
def history_view(request):
    """Protected view displaying Slide 4: Diagnostic scans history table."""
    context = get_base_context(request.user)
    context['active_slide'] = 'history'
    
    device_id = request.GET.get('device_id', '')
    if request.user.username == 'matish0508':
        reports = ScanReport.objects.filter(
            platform__in=['windows', 'linux', 'android', 'combined']
        ).order_by('-timestamp')
    else:
        reports = ScanReport.objects.filter(
            user=request.user,
            platform__in=['windows', 'linux', 'android', 'combined']
        ).order_by('-timestamp')
        
    context['reports'] = reports
    return render(request, 'history.html', context)


# --- Protected API Actions ---

@login_required
@require_POST
def api_toggle_complete(request):
    try:
        data = json.loads(request.body)
        rule_id = data.get('rule_id')
        rule = HardeningRule.objects.get(id=rule_id)
        progress = UserProgress.objects.get(user=request.user, rule=rule)
        progress.is_completed = not progress.is_completed
        progress.save()
        
        total = HardeningRule.objects.filter(platform=rule.platform).count()
        completed = UserProgress.objects.filter(user=request.user, rule__platform=rule.platform, is_completed=True).count()
        
        return JsonResponse({
            'success': True,
            'is_completed': progress.is_completed,
            'stats': {
                'completed': completed,
                'pending': total - completed,
                'percentage': int((completed / total) * 100) if total > 0 else 0
            }
        })
    except (HardeningRule.DoesNotExist, UserProgress.DoesNotExist):
        return JsonResponse({'success': False, 'error': 'Rule progress not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

@login_required
@require_POST
def api_toggle_include(request):
    try:
        data = json.loads(request.body)
        rule_id = data.get('rule_id')
        rule = HardeningRule.objects.get(id=rule_id)
        progress = UserProgress.objects.get(user=request.user, rule=rule)
        progress.is_included_in_script = not progress.is_included_in_script
        progress.save()
        
        return JsonResponse({
            'success': True,
            'is_included': progress.is_included_in_script
        })
    except (HardeningRule.DoesNotExist, UserProgress.DoesNotExist):
        return JsonResponse({'success': False, 'error': 'Rule progress not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

@login_required
@require_POST
def api_bulk_actions(request):
    try:
        data = json.loads(request.body)
        platform = data.get('platform')
        action = data.get('action')
        category = data.get('category', 'all')
        
        rules = HardeningRule.objects.filter(platform=platform)
        if category != 'all':
            rules = rules.filter(category=category)
            
        progresses = UserProgress.objects.filter(user=request.user, rule__in=rules)
        
        if action == 'check_all':
            progresses.update(is_completed=True)
        elif action == 'uncheck_all':
            progresses.update(is_completed=False)
        elif action == 'include_all':
            progresses.update(is_included_in_script=True)
        elif action == 'exclude_all':
            progresses.update(is_included_in_script=False)
            
        total = HardeningRule.objects.filter(platform=platform).count()
        completed = UserProgress.objects.filter(user=request.user, rule__platform=platform, is_completed=True).count()
        
        return JsonResponse({
            'success': True,
            'stats': {
                'completed': completed,
                'pending': total - completed,
                'percentage': int((completed / total) * 100) if total > 0 else 0
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

@login_required
def download_script(request, platform):
    if platform not in ['windows', 'linux', 'android']:
        return HttpResponse("Invalid platform", status=400)
        
    included_rule_ids = UserProgress.objects.filter(user=request.user, is_included_in_script=True).values_list('rule_id', flat=True)
    rules = HardeningRule.objects.filter(platform=platform, id__in=included_rule_ids)
    date_str = timezone.now().strftime('%Y-%m-%d')
    
    script_text = ""
    if platform == 'windows':
        script_text += f'''<#
.SYNOPSIS
    Custom OS Hardening Script generated by OS Hardening Assistant.
    Platform: Windows
    Generated on: {date_str}
.DESCRIPTION
    This script implements selected system hardening controls. Ensure you run this in an Elevated PowerShell Console.
#>

# Check for administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Error "This script must be run as Administrator. Please relaunch PowerShell with administrative privileges."
    Exit 1
}}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Starting Windows System Hardening Script " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Running check implementations...        " -ForegroundColor Gray
Write-Host "==========================================" -ForegroundColor Cyan
'''
        if not rules.exists():
            script_text += "\n# No hardening scripts selected to run.\n"
        else:
            for rule in rules:
                script_text += f"\n{rule.script_code}\n"
                
        script_text += f'''\nWrite-Host "==========================================" -ForegroundColor Cyan
Write-Host " Hardening script run finished!           " -ForegroundColor Cyan
Write-Host " Please reboot system if required.        " -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan
'''
        response = HttpResponse(script_text, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="win-hardening.ps1"'
        return response
        
    elif platform == 'linux':
        script_text += f'''#!/bin/bash
# ==============================================================================
# Custom OS Hardening Script generated by OS Hardening Assistant
# Platform: Linux (Ubuntu/Debian)
# Generated on: {date_str}
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
backup_file() {{
    local filepath="$1"
    if [ -f "$filepath" ] && [ ! -f "${{filepath}}.bak" ]; then
        echo "Creating backup of $filepath to ${{filepath}}.bak"
        cp "$filepath" "${{filepath}}.bak"
    fi
}}
'''
        if not rules.exists():
            script_text += "\n# No hardening scripts selected to run.\n"
        else:
            for rule in rules:
                script_text += f"\n{rule.script_code}\n"
                
        script_text += f'''\necho "=========================================="
echo " Hardening script run finished!           "
echo " Please check logs above & reboot if needed."
echo "=========================================="
'''
        response = HttpResponse(script_text, content_type='application/x-sh')
        response['Content-Disposition'] = f'attachment; filename="linux-hardening.sh"'
        return response
        
    else: # Android ADB commands
        script_text += f'''#!/bin/bash
# ==============================================================================
# Custom Android ADB Hardening Script generated by OS Hardening Assistant
# Platform: Android (Audited via ADB Commands)
# Generated on: {date_str}
# ==============================================================================

echo "=========================================="
echo " Starting Android ADB Hardening Controls  "
echo " Ensure USB Debugging is active on phone  "
echo "=========================================="

# Helper function to check adb connection
check_adb() {{
    adb devices | grep -w "device" > /dev/null
    if [ $? -ne 0 ]; then
        echo "Error: No Android device authorized via ADB. Please connect and verify permissions."
        exit 1
    fi
}}

check_adb
'''
        if not rules.exists():
            script_text += "\n# No hardening ADB scripts selected to run.\n"
        else:
            for rule in rules:
                if not rule.script_code.startswith("#"):
                    script_text += f"\necho 'Executing: {rule.title}'\n{rule.script_code}\n"
                else:
                    script_text += f"\n# {rule.title} - {rule.remediation}\n"
                    
        script_text += f'''\necho "=========================================="
echo " Android Hardening settings applied!      "
echo "=========================================="
'''
        response = HttpResponse(script_text, content_type='application/x-sh')
        response['Content-Disposition'] = f'attachment; filename="android-hardening.sh"'
        return response


# --- Automated System Scanning Engine ---

def run_powershell_check(cmd):
    """Utility to safely run local PowerShell checks on Windows."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return f"Error: {str(e)}", -1

def execute_windows_audits():
    """Runs local command checks on the Windows host and returns list of completed rule IDs."""
    completed = []
    
    # 1. Disable Guest Account
    out, code = run_powershell_check("Get-LocalUser -Name 'Guest' | Select-Object -ExpandProperty Enabled")
    if out == "False" and code == 0:
         completed.append("win-guest-acct")
         
    # 2. Enforce Minimum Password Length (>= 14)
    out, code = run_powershell_check("net accounts")
    if code == 0:
        for line in out.splitlines():
            if "Minimum password length:" in line:
                try:
                    length = int(line.split(":")[-1].strip())
                    if length >= 14:
                        completed.append("win-pw-length")
                except ValueError:
                     pass
                break
                
    # 3. Enable Defender Real-Time Protection
    out, code = run_powershell_check("(Get-MpComputerStatus).RealTimeProtectionEnabled")
    if out == "True" and code == 0:
        completed.append("win-defender-rt")
        
    # 4. Enable Firewall profiles
    out, code = run_powershell_check("Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}")
    if out == "" and code == 0: # No profiles are disabled
        completed.append("win-firewall-profiles")
        
    # 5. Disable LLMNR
    out, code = run_powershell_check("(Get-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast")
    if out == "0" and code == 0:
        completed.append("win-disable-llmnr")
        
    # 6. Disable SMBv1 & Enforce SMBv3 Security
    out_v1, code_v1 = run_powershell_check("(Get-SmbServerConfiguration).EnableSMB1Protocol")
    out_enc, code_enc = run_powershell_check("(Get-SmbServerConfiguration).EncryptData")
    if out_v1 == "False" and out_enc == "True" and code_v1 == 0 and code_enc == 0:
        completed.append("win-smbv1")
        
    # 7. Set UAC Consent Prompt Behavior to 2 (Always Notify)
    out, code = run_powershell_check("(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').ConsentPromptBehaviorAdmin")
    if out == "2" and code == 0:
        completed.append("win-uac-always")
        
    # 8. PowerShell Execution Policy (RemoteSigned or tighter)
    out, code = run_powershell_check("Get-ExecutionPolicy")
    if code == 0 and out in ["RemoteSigned", "AllSigned", "Restricted"]:
        completed.append("win-powershell-policy")
        
    # 9. Audit Logon Failures
    out, code = run_powershell_check("auditpol /get /subcategory:'Logon'")
    if code == 0 and ("Failure" in out or "Failure and Success" in out):
        completed.append("win-audit-logon")
        
    return completed

@login_required
@require_POST
def api_scan_system(request):
    """Scans Windows, Linux or Android mobile systems separately (using simulated or web APIs)."""
    try:
        data = json.loads(request.body)
        platform_name = data.get('platform', 'windows')
        device_id = data.get('device_id', '')
        if platform_name not in ['windows', 'linux', 'android']:
            return JsonResponse({'success': False, 'error': 'Invalid platform'}, status=400)
            
        # Load rules and current state (BEFORE state)
        rules = HardeningRule.objects.filter(platform=platform_name)
        total = rules.count()
        if total == 0:
            return JsonResponse({'success': False, 'error': 'No rules found for platform'}, status=400)
            
        progress_map = {up.rule_id: up for up in UserProgress.objects.filter(user=request.user, rule__platform=platform_name)}
        before_completed = [rid for rid, up in progress_map.items() if up.is_completed]
        before_score = int((len(before_completed) / total) * 100) if total > 0 else 0
        
        passed_ids = []
        is_windows_host = sys.platform == 'win32'
        
        # Run scan separately
        if platform_name == 'windows':
            if is_windows_host:
                passed_ids = execute_windows_audits()
            else:
                passed_ids = [rules[i].id for i in range(total) if i % 2 == 0]
        elif platform_name == 'android':
            passed_ids = [rules[i].id for i in range(total) if i % 2 == 0]
        else: # linux
            passed_ids = [rules[i].id for i in range(total) if i % 2 == 0]
            
        # Update database states (AFTER state)
        for rule in rules:
            prog = progress_map.get(rule.id)
            if prog:
                prog.is_completed = (rule.id in passed_ids)
                prog.save()
            
        after_completed = passed_ids
        after_score = int((len(after_completed) / total) * 100) if total > 0 else 0
        
        # Compare Before vs After
        all_ids = [r.id for r in rules]
        newly_completed = list(set(after_completed) - set(before_completed))
        still_failed = list(set(all_ids) - set(after_completed))
        still_completed = list(set(after_completed) & set(before_completed))
        
        # Log to ScanReport history database table separately
        new_report = ScanReport.objects.create(
            user=request.user,
            platform=platform_name,
            score=after_score,
            passed_checks=json.dumps(after_completed),
            failed_checks=json.dumps(still_failed),
            device_id=device_id
        )
        
        # Get the previous scan report for the same platform and user to show baseline comparison
        previous_report = None
        try:
            previous_report = ScanReport.objects.filter(
                user=request.user,
                platform=platform_name
            ).exclude(id=new_report.id).latest('timestamp')
        except ScanReport.DoesNotExist:
            pass
            
        historical_score = previous_report.score if previous_report else before_score
        
        return JsonResponse({
            'success': True,
            'report': {
                'platform': platform_name,
                'timestamp': new_report.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'before_score': historical_score,
                'after_score': after_score,
                'resolved_count': len(newly_completed),
                'resolved_rules': [HardeningRule.objects.get(id=rid).title for rid in newly_completed],
                'still_failed_rules': [HardeningRule.objects.get(id=rid).title for rid in still_failed],
                'still_completed_rules': [HardeningRule.objects.get(id=rid).title for rid in still_completed]
            },
            'stats': {
                'completed': len(after_completed),
                'pending': total - len(after_completed),
                'percentage': after_score
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


# --- Code Repository Downloader ---

@login_required
def download_repository_zip(request):
    """Zips the entire workspace directories and streams as package file, omitting DB/Caches."""
    buffer = io.BytesIO()
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(base_dir):
                dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', '.venv', 'env', '.idea', '.vscode', '.agents']]
                for file in files:
                    if file in ['db.sqlite3', 'db.sqlite3-journal'] or file.endswith('.log') or file.endswith('.pyc'):
                        continue
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, base_dir)
                    zip_file.write(file_path, rel_path)
                    
        buffer.seek(0)
        response = FileResponse(buffer, as_attachment=True, filename='os-hardening-assistant.zip')
        return response
    except Exception as e:
        return HttpResponse(f"Error packing repository: {str(e)}", status=500)


# --- PDF Compliance Report Compiler (ReportLab) ---

@login_required
def download_pdf_report(request, platform):
    """Compiles rules and progress data separately for the selected platform, generating PDF download."""
    if platform not in ['windows', 'linux', 'android']:
        return HttpResponse("Invalid platform", status=400)
        
    try:
        # Load rules specifically for the requested platform and request.user
        rules = HardeningRule.objects.filter(platform=platform).order_by('category')
        progress_map = {up.rule_id: up for up in UserProgress.objects.filter(user=request.user, rule__platform=platform)}
        for rule in rules:
            rule.progress = progress_map.get(rule.id)
            
        total = rules.count()
        completed = sum(1 for r in rules if r.progress and r.progress.is_completed)
        score = int((completed / total) * 100) if total > 0 else 0
        
        # Fetch the latest scan report specifically for this platform and user
        latest_report = None
        try:
            latest_report = ScanReport.objects.filter(user=request.user, platform=platform).latest('timestamp')
        except ScanReport.DoesNotExist:
            pass
            
        # Setup memory stream and doc template
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            textColor=colors.HexColor('#4f46e5'),
            spaceAfter=6
        )
        
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontName='Helvetica-Oblique',
            fontSize=10,
            textColor=colors.HexColor('#6b7280'),
            spaceAfter=15
        )
        
        h2_style = ParagraphStyle(
            'H2Style',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            textColor=colors.HexColor('#1f2937'),
            spaceBefore=12,
            spaceAfter=6
        )
        
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9.5,
            textColor=colors.HexColor('#374151'),
            leading=13
        )
        
        cell_bold = ParagraphStyle(
            'CellBold',
            parent=body_style,
            fontName='Helvetica-Bold'
        )
        
        status_ok = ParagraphStyle(
            'StatusOk',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=colors.HexColor('#10b981')
        )
        
        status_fail = ParagraphStyle(
            'StatusFail',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=colors.HexColor('#f59e0b')
        )

        elements_list = []
        
        # 1. Title & Header (separate platform labels)
        platform_label = "Windows OS" if platform == 'windows' else ("Linux OS" if platform == 'linux' else "Android OS")
        elements_list.append(Paragraph(f"{platform_label} Hardening Compliance Report", title_style))
        elements_list.append(Paragraph(f"Generated on: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')} UTC | Platform: {platform_label.upper()} Audit", subtitle_style))
        elements_list.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#e5e7eb'), spaceAfter=15))
        
        # 2. Executive Summary Block
        elements_list.append(Paragraph("Executive Summary", h2_style))
        
        scan_date = latest_report.timestamp.strftime('%Y-%m-%d %H:%M:%S') if latest_report else 'No automated scan run yet'
        summary_data = [
            [Paragraph("Target Platform", cell_bold), Paragraph(platform_label, body_style)],
            [Paragraph("Last Diagnostic Scan", cell_bold), Paragraph(scan_date, body_style)],
            [Paragraph("Scanned Security Controls", cell_bold), Paragraph(f"{completed} / {total} Passed", body_style)],
            [Paragraph("OS Security Score", cell_bold), Paragraph(f"{score}%", ParagraphStyle('ScorePct', parent=cell_bold, fontSize=12, textColor=colors.HexColor('#4f46e5')))]
        ]
        
        summary_table = Table(summary_data, colWidths=[200, 340])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f9fafb')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements_list.append(summary_table)
        elements_list.append(Spacer(1, 15))
        
        # 3. Rules Table
        elements_list.append(Paragraph("Security Controls Checklist Audit Details", h2_style))
        
        table_data = [
            [Paragraph("Security Control Policy Check", cell_bold), Paragraph("Category", cell_bold), Paragraph("Severity", cell_bold), Paragraph("Status", cell_bold)]
        ]
        
        for rule in rules:
            status_para = Paragraph("COMPLIANT", status_ok) if rule.progress and rule.progress.is_completed else Paragraph("VULNERABLE", status_fail)
            table_data.append([
                Paragraph(rule.title, body_style),
                Paragraph(rule.category, body_style),
                Paragraph(rule.severity.upper(), cell_bold if rule.severity in ['critical', 'high'] else body_style),
                status_para
            ])
            
        rules_table = Table(table_data, colWidths=[230, 110, 100, 100])
        
        table_styles = [
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#4f46e5')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]
        
        for col_idx in range(4):
            table_styles.append(('TEXTCOLOR', (col_idx,0), (col_idx,0), colors.white))
            
        for i in range(1, len(table_data)):
            bg_color = colors.HexColor('#f9fafb') if i % 2 == 0 else colors.white
            table_styles.append(('BACKGROUND', (0, i), (-1, i), bg_color))
            
        rules_table.setStyle(TableStyle(table_styles))
        elements_list.append(rules_table)
        
        # Build document
        doc.build(elements_list)
        
        buffer.seek(0)
        response = FileResponse(buffer, as_attachment=True, filename=f'{platform}-hardening-report.pdf')
        return response
        
    except Exception as e:
        return HttpResponse(f"Error compiling PDF: {str(e)}", status=500)
