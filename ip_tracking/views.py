from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.views import View
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from .models import RequestLog, BlockedIP, SuspiciousIP
import json


def ratelimit_handler(request, exception):
    """Custom handler for rate limit exceeded"""
    if request.content_type == 'application/json':
        return JsonResponse({
            'error': 'Rate limit exceeded. Please try again later.'
        }, status=429)
    else:
        return HttpResponseForbidden("Rate limit exceeded. Please try again later.")


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request):
    """
    Login view with rate limiting - 5 requests per minute for anonymous users
    Authenticated users get higher limits through middleware or decorator stacking
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Login successful!')
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid credentials')
        else:
            messages.error(request, 'Please provide both username and password')
    
    return render(request, 'ip_tracking/login.html')


@ratelimit(key='ip', rate='10/m', method=['GET', 'POST'], block=True)
@login_required
def dashboard_view(request):
    """
    Dashboard view with rate limiting - 10 requests per minute for authenticated users
    """
    recent_logs = RequestLog.objects.filter(
        ip_address=get_client_ip(request)
    ).order_by('-timestamp')[:10]
    
    context = {
        'recent_logs': recent_logs,
        'user_ip': get_client_ip(request),
    }
    
    return render(request, 'ip_tracking/dashboard.html', context)


@ratelimit(key='ip', rate='3/m', method=['GET', 'POST'], block=True)
def sensitive_api_view(request):
    """
    Sensitive API endpoint with strict rate limiting - 3 requests per minute
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            # Process sensitive data here
            return JsonResponse({
                'status': 'success',
                'message': 'Data processed successfully'
            })
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON data'
            }, status=400)
    
    return JsonResponse({
        'status': 'info',
        'message': 'Sensitive API endpoint - POST requests only'
    })


@login_required
def admin_logs_view(request):
    """
    Admin view to see request logs and suspicious activities
    """
    if not request.user.is_staff:
        return HttpResponseForbidden("Access denied")
    
    # Get recent logs
    recent_logs = RequestLog.objects.all().order_by('-timestamp')[:100]
    
    # Get suspicious IPs
    suspicious_ips = SuspiciousIP.objects.filter(
        is_reviewed=False
    ).order_by('-detected_at')
    
    # Get blocked IPs
    blocked_ips = BlockedIP.objects.all().order_by('-created_at')
    
    context = {
        'recent_logs': recent_logs,
        'suspicious_ips': suspicious_ips,
        'blocked_ips': blocked_ips,
    }
    
    return render(request, 'ip_tracking/admin_logs.html', context)


def get_client_ip(request):
    """Helper function to get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@csrf_exempt
@ratelimit(key='ip', rate='2/m', method='POST', block=True)
def webhook_view(request):
    """
    Webhook endpoint with very strict rate limiting - 2 requests per minute
    """
    if request.method == 'POST':
        try:
            # Process webhook data
            data = json.loads(request.body)
            
            # Log webhook access
            RequestLog.objects.create(
                ip_address=get_client_ip(request),
                path=request.path + ' [WEBHOOK]'
            )
            
            return JsonResponse({'status': 'received'})
            
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    return JsonResponse({
        'status': 'error',
        'message': 'POST requests only'
    }, status=405)


class RateLimitedView(View):
    """
    Class-based view with rate limiting applied via method decorator
    """
    
    @method_decorator(ratelimit(key='ip', rate='5/m', method='GET', block=True))
    def get(self, request):
        return JsonResponse({
            'message': 'This is a rate-limited class-based view',
            'ip': get_client_ip(request)
        })
    
    @method_decorator(ratelimit(key='ip', rate='3/m', method='POST', block=True))
    def post(self, request):
        return JsonResponse({
            'message': 'POST request received',
            'ip': get_client_ip(request)
        })