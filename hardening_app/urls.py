from django.urls import path
from . import views

urlpatterns = [
    path('', views.index_view, name='index'),
    path('api/toggle-complete/', views.api_toggle_complete, name='api_toggle_complete'),
    path('api/toggle-include/', views.api_toggle_include, name='api_toggle_include'),
    path('api/bulk-actions/', views.api_bulk_actions, name='api_bulk_actions'),
    path('download-script/<str:platform>/', views.download_script, name='download_script'),
]
