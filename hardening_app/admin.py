from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import HardeningRule, UserProgress, ScanReport

# Unregister the default User admin and re-register with date_joined and last_login visible
admin.site.unregister(User)

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    def get_plaintext_password(self, obj):
        try:
            return obj.profile.plaintext_password
        except Exception:
            return "-"
    get_plaintext_password.short_description = 'Plaintext Password'

    list_display = ('username', 'email', 'get_plaintext_password', 'date_joined', 'last_login', 'is_staff', 'is_superuser')
    ordering = ('-date_joined',)

@admin.register(HardeningRule)
class HardeningRuleAdmin(admin.ModelAdmin):
    list_display = ('id', 'platform', 'title', 'category', 'severity')
    list_filter = ('platform', 'severity', 'category')
    search_fields = ('id', 'title', 'description', 'remediation')

@admin.register(UserProgress)
class UserProgressAdmin(admin.ModelAdmin):
    list_display = ('user', 'rule', 'is_completed', 'is_included_in_script')
    list_filter = ('is_completed', 'is_included_in_script', 'rule__platform')
    search_fields = ('user__username', 'rule__id', 'rule__title')

@admin.register(ScanReport)
class ScanReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'platform', 'score', 'timestamp', 'device_id')
    list_filter = ('platform', 'timestamp')
    search_fields = ('user__username', 'device_id')
