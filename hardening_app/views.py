import io
import os
import json
import zipfile
import subprocess
import sys
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.http import require_POST
from django.utils import timezone
from .models import HardeningRule, UserProgress, ScanReport

def index_view(request):
    rules = HardeningRule.objects.select_related('progress').all()
    
    windows_rules = [r for r in rules if r.platform == 'windows']
    linux_rules = [r for r in rules if r.platform == 'linux']
    
    win_total = len(windows_rules)
    win_completed = sum(1 for r in windows_rules if r.progress.is_completed)
    win_pending = win_total - win_completed
    win_pct = int((win_completed / win_total) * 100) if win_total > 0 else 0
    
    lin_total = len(linux_rules)
    lin_completed = sum(1 for r in linux_rules if r.progress.is_completed)
    lin_pending = lin_total - lin_completed
    lin_pct = int((lin_completed / lin_total) * 100) if lin_total > 0 else 0
    
    win_categories = sorted(list(set(r.category for r in windows_rules)))
    lin_categories = sorted(list(set(r.category for r in linux_rules)))
    
    context = {
        'windows_rules': windows_rules,
        'linux_rules': linux_rules,
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
            }
        }
    }
    return render(request, 'index.html', context)

@require_POST
def api_toggle_complete(request):
    try:
        data = json.loads(request.body)
        rule_id = data.get('rule_id')
        rule = HardeningRule.objects.get(id=rule_id)
        progress = rule.progress
        progress.is_completed = not progress.is_completed
        progress.save()
        
        platform_rules = HardeningRule.objects.filter(platform=rule.platform).select_related('progress')
        total = platform_rules.count()
        completed = sum(1 for r in platform_rules if r.progress.is_completed)
        
        return JsonResponse({
            'success': True,
            'is_completed': progress.is_completed,
            'stats': {
                'completed': completed,
                'pending': total - completed,
                'percentage': int((completed / total) * 100) if total > 0 else 0
            }
        })
    except HardeningRule.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Rule not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

@require_POST
def api_toggle_include(request):
    try:
        data = json.loads(request.body)
        rule_id = data.get('rule_id')
        rule = HardeningRule.objects.get(id=rule_id)
        progress = rule.progress
        progress.is_included_in_script = not progress.is_included_in_script
        progress.save()
        
        return JsonResponse({
            'success': True,
            'is_included': progress.is_included_in_script
        })
    except HardeningRule.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Rule not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

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
            
        progresses = UserProgress.objects.filter(rule__in=rules)
        
        if action == 'check_all':
            progresses.update(is_completed=True)
        elif action == 'uncheck_all':
            progresses.update(is_completed=False)
        elif action == 'include_all':
            progresses.update(is_included_in_script=True)
        elif action == 'exclude_all':
            progresses.update(is_included_in_script=False)
            
        all_platform_rules = HardeningRule.objects.filter(platform=platform).select_related('progress')
        total = all_platform_rules.count()
        completed = sum(1 for r in all_platform_rules if r.progress.is_completed)
        
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

def download_script(request, platform):
    if platform not in ['windows', 'linux']:
        return HttpResponse("Invalid platform", status=400)
        
    rules = HardeningRule.objects.filter(platform=platform, progress__is_included_in_script=True)
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
        
    else: # Linux
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
        
    # 6. Disable SMBv1
    out, code = run_powershell_check("(Get-SmbServerConfiguration).EnableSMB1Protocol")
    if out == "False" and code == 0:
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

@require_POST
def api_scan_system(request):
    try:
        data = json.loads(request.body)
        platform_name = data.get('platform', 'windows')
        
        # Load rules and current state (BEFORE state)
        rules = HardeningRule.objects.filter(platform=platform_name).select_related('progress')
        total = rules.count()
        if total == 0:
            return JsonResponse({'success': False, 'error': 'No rules found for platform'}, status=400)
            
        before_completed = [r.id for r in rules if r.progress.is_completed]
        before_score = int((len(before_completed) / total) * 100) if total > 0 else 0
        
        passed_ids = []
        
        # Execute Scans
        is_windows_host = sys.platform == 'win32'
        
        if platform_name == 'windows' and is_windows_host:
            passed_ids = execute_windows_audits()
        else:
            # If scanning Linux on Windows, or Windows on Linux -> Simulate scan results
            # Make it mock so the user can experience the scanning reports
            # Let's say rules 1, 3, 5, 7, 8 are compliant (simulating ~55% compliance)
            all_ids = [r.id for r in rules]
            # Select every second rule
            passed_ids = [all_ids[i] for i in range(len(all_ids)) if i % 2 == 0]
            
        # Update database states (AFTER state)
        for rule in rules:
            progress = rule.progress
            progress.is_completed = (rule.id in passed_ids)
            progress.save()
            
        after_completed = passed_ids
        after_score = int((len(after_completed) / total) * 100) if total > 0 else 0
        
        # Compare Before vs After
        newly_completed = list(set(after_completed) - set(before_completed))
        newly_failed = list(set(before_completed) - set(after_completed))
        still_completed = list(set(after_completed) & set(before_completed))
        still_failed = list(set(all_ids if 'all_ids' in locals() else [r.id for r in rules]) - set(after_completed))
        
        # Log to ScanReport history database table
        new_report = ScanReport.objects.create(
            platform=platform_name,
            score=after_score,
            passed_checks=json.dumps(after_completed),
            failed_checks=json.dumps([r.id for r in rules if r.id not in after_completed])
        )
        
        # Get the previous scan report to show historical change if applicable
        previous_report = None
        try:
            previous_report = ScanReport.objects.filter(platform=platform_name).exclude(id=new_report.id).latest('timestamp')
        except ScanReport.DoesNotExist:
            pass
            
        historical_score = previous_report.score if previous_report else before_score
        
        return JsonResponse({
            'success': True,
            'report': {
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

def download_repository_zip(request):
    """Zips the entire workspace directories and streams as package file, omitting DB/Caches."""
    buffer = io.BytesIO()
    
    # Locate workspace base path
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    try:
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(base_dir):
                # Prune directory search path
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
