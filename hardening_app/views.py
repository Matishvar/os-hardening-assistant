import json
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST
from django.utils import timezone
from .models import HardeningRule, UserProgress

def index_view(request):
    # Retrieve all rules and prefetch user progress
    rules = HardeningRule.objects.select_related('progress').all()
    
    # Organize rules by platform
    windows_rules = [r for r in rules if r.platform == 'windows']
    linux_rules = [r for r in rules if r.platform == 'linux']
    
    # Calculate stats for Windows
    win_total = len(windows_rules)
    win_completed = sum(1 for r in windows_rules if r.progress.is_completed)
    win_pending = win_total - win_completed
    win_pct = int((win_completed / win_total) * 100) if win_total > 0 else 0
    
    # Calculate stats for Linux
    lin_total = len(linux_rules)
    lin_completed = sum(1 for r in linux_rules if r.progress.is_completed)
    lin_pending = lin_total - lin_completed
    lin_pct = int((lin_completed / lin_total) * 100) if lin_total > 0 else 0
    
    # Extract unique categories
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
        
        # Recalculate stats for the platform
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
        action = data.get('action') # 'check_all', 'uncheck_all', 'include_all', 'exclude_all'
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
            
        # Recalculate stats
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
