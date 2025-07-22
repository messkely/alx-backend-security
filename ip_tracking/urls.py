from django.urls import path
from . import views

app_name = 'ip_tracking'

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('admin-logs/', views.admin_logs_view, name='admin_logs'),
    path('api/sensitive/', views.sensitive_api_view, name='sensitive_api'),
    path('webhook/', views.webhook_view, name='webhook'),
    path('rate-limited/', views.RateLimitedView.as_view(), name='rate_limited'),
]
