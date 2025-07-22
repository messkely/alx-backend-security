import logging
import requests
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.conf import settings
from .models import RequestLog, BlockedIP

logger = logging.getLogger(__name__)


class IPTrackingMiddleware:
    """
    Middleware to track IP addresses, log requests, and block blacklisted IPs
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Get client IP address
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            logger.warning(f"Blocked request from IP: {ip_address}")
            return HttpResponseForbidden("Access denied: IP address is blocked")
        
        # Get geolocation data
        country, city = self.get_geolocation(ip_address)
        
        # Log the request
        try:
            RequestLog.objects.create(
                ip_address=ip_address,
                path=request.path,
                country=country,
                city=city
            )
        except Exception as e:
            logger.error(f"Failed to log request: {e}")
        
        response = self.get_response(request)
        return response
    
    def get_client_ip(self, request):
        """Extract client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def is_ip_blocked(self, ip_address):
        """Check if IP address is in the blocked list"""
        try:
            # Use cache to avoid database hits for every request
            cache_key = f"blocked_ip_{ip_address}"
            is_blocked = cache.get(cache_key)
            
            if is_blocked is None:
                is_blocked = BlockedIP.objects.filter(ip_address=ip_address).exists()
                # Cache for 1 hour
                cache.set(cache_key, is_blocked, 3600)
            
            return is_blocked
        except Exception as e:
            logger.error(f"Error checking blocked IP: {e}")
            return False
    
    def get_geolocation(self, ip_address):
        """Get geolocation data for IP address with caching"""
        if ip_address in ['127.0.0.1', '::1', 'localhost']:
            return 'Local', 'Local'
        
        cache_key = f"geolocation_{ip_address}"
        geolocation_data = cache.get(cache_key)
        
        if geolocation_data is None:
            try:
                # Using a free geolocation API (ip-api.com)
                response = requests.get(
                    f"http://ip-api.com/json/{ip_address}",
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        country = data.get('country', 'Unknown')
                        city = data.get('city', 'Unknown')
                        geolocation_data = (country, city)
                    else:
                        geolocation_data = ('Unknown', 'Unknown')
                else:
                    geolocation_data = ('Unknown', 'Unknown')
                
                # Cache for 24 hours
                cache.set(cache_key, geolocation_data, 86400)
                
            except Exception as e:
                logger.error(f"Failed to get geolocation for {ip_address}: {e}")
                geolocation_data = ('Unknown', 'Unknown')
        
        return geolocation_data