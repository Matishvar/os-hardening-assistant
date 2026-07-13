from django.urls import path
from . import views

urlpatterns = [
    # Authentication endpoints
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('forgot-username/', views.forgot_username_view, name='forgot_username'),
    path('logout/', views.logout_view, name='logout'),
    
    # Slide panel views
    path('', views.dashboard_view, name='dashboard'),
    path('checklist/', views.checklist_view, name='checklist'),
    path('script/', views.script_view, name='script'),
    path('history/', views.history_view, name='history'),
    
    # REST API endpoints
    path('api/toggle-complete/', views.api_toggle_complete, name='api_toggle_complete'),
    path('api/toggle-include/', views.api_toggle_include, name='api_toggle_include'),
    path('api/bulk-actions/', views.api_bulk_actions, name='api_bulk_actions'),
    path('api/scan/', views.api_scan_system, name='api_scan_system'),
    path('api/download-repo/', views.download_repository_zip, name='download_repo'),
    path('api/download-pdf/<str:platform>/', views.download_pdf_report, name='download_pdf'),
    path('download-script/<str:platform>/', views.download_script, name='download_script'),
]

# Force-seed credentials on startup when urls are loaded
try:
    views.ensure_default_user_and_rules()
except Exception as e:
    print("Warning: Failed to seed admin user on startup load:", e)
