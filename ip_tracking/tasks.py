from celery import shared_task
from django.utils import timezone
from django.db.models import Count
from datetime import timedelta
from .models import RequestLog, SuspiciousIP, BlockedIP
import logging

logger = logging.getLogger(__name__)


@shared_task
def detect_anomalies():
    """
    Celery task to detect suspicious IP behavior
    Runs hourly to analyze request patterns
    """
    logger.info("Starting anomaly detection task")
    
    # Get the time range for analysis (last hour)
    end_time = timezone.now()
    start_time = end_time - timedelta(hours=1)
    
    # Detect high volume IPs
    detect_high_volume_ips(start_time, end_time)
    
    # Detect sensitive path access
    detect_sensitive_path_access(start_time, end_time)
    
    # Detect suspicious patterns
    detect_suspicious_patterns(start_time, end_time)
    
    logger.info("Anomaly detection task completed")
    return "Anomaly detection completed successfully"


def detect_high_volume_ips(start_time, end_time):
    """
    Detect IPs that exceed 100 requests per hour
    """
    high_volume_threshold = 100
    
    # Get IPs with high request volume
    high_volume_ips = RequestLog.objects.filter(
        timestamp__gte=start_time,
        timestamp__lt=end_time
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=high_volume_threshold)
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        # Skip if IP is already blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            continue
        
        # Check if this anomaly was already flagged recently
        recent_flag = SuspiciousIP.objects.filter(
            ip_address=ip_address,
            reason__contains='High volume',
            detected_at__gte=timezone.now() - timedelta(hours=24)
        ).exists()
        
        if not recent_flag:
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f'High volume: {request_count} requests in 1 hour (threshold: {high_volume_threshold})'
            )
            logger.warning(f"Flagged high volume IP: {ip_address} ({request_count} requests)")


def detect_sensitive_path_access(start_time, end_time):
    """
    Detect IPs accessing sensitive paths like /admin, /login
    """
    sensitive_paths = ['/admin', '/login', '/api/admin', '/wp-admin', '/phpmyadmin']
    sensitive_threshold = 5  # More than 5 attempts to sensitive paths
    
    for path_pattern in sensitive_paths:
        suspicious_ips = RequestLog.objects.filter(
            timestamp__gte=start_time,
            timestamp__lt=end_time,
            path__icontains=path_pattern
        ).values('ip_address').annotate(
            access_count=Count('id')
        ).filter(access_count__gt=sensitive_threshold)
        
        for ip_data in suspicious_ips:
            ip_address = ip_data['ip_address']
            access_count = ip_data['access_count']
            
            # Skip if IP is already blocked
            if BlockedIP.objects.filter(ip_address=ip_address).exists():
                continue
            
            # Check if this anomaly was already flagged recently
            recent_flag = SuspiciousIP.objects.filter(
                ip_address=ip_address,
                reason__contains=f'Sensitive path access: {path_pattern}',
                detected_at__gte=timezone.now() - timedelta(hours=24)
            ).exists()
            
            if not recent_flag:
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=f'Sensitive path access: {path_pattern} ({access_count} attempts)'
                )
                logger.warning(f"Flagged sensitive path access: {ip_address} -> {path_pattern} ({access_count} times)")


def detect_suspicious_patterns(start_time, end_time):
    """
    Detect other suspicious patterns like:
    - Multiple different paths from same IP (potential scanning)
    - Rapid requests (potential bot activity)
    """
    
    # Detect potential path scanning
    scanning_threshold = 20  # More than 20 different paths
    
    scanning_ips = RequestLog.objects.filter(
        timestamp__gte=start_time,
        timestamp__lt=end_time
    ).values('ip_address').annotate(
        unique_paths=Count('path', distinct=True),
        total_requests=Count('id')
    ).filter(unique_paths__gt=scanning_threshold)
    
    for ip_data in scanning_ips:
        ip_address = ip_data['ip_address']
        unique_paths = ip_data['unique_paths']
        total_requests = ip_data['total_requests']
        
        # Skip if IP is already blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            continue
        
        # Check if this anomaly was already flagged recently
        recent_flag = SuspiciousIP.objects.filter(
            ip_address=ip_address,
            reason__contains='Path scanning',
            detected_at__gte=timezone.now() - timedelta(hours=24)
        ).exists()
        
        if not recent_flag:
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f'Path scanning: {unique_paths} unique paths in {total_requests} requests'
            )
            logger.warning(f"Flagged path scanning: {ip_address} ({unique_paths} paths)")
    
    # Detect rapid requests (potential bot)
    rapid_threshold = 50  # More than 50 requests in 10 minutes
    rapid_start_time = end_time - timedelta(minutes=10)
    
    rapid_ips = RequestLog.objects.filter(
        timestamp__gte=rapid_start_time,
        timestamp__lt=end_time
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=rapid_threshold)
    
    for ip_data in rapid_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        # Skip if IP is already blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            continue
        
        # Check if this anomaly was already flagged recently
        recent_flag = SuspiciousIP.objects.filter(
            ip_address=ip_address,
            reason__contains='Rapid requests',
            detected_at__gte=timezone.now() - timedelta(hours=1)
        ).exists()
        
        if not recent_flag:
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f'Rapid requests: {request_count} requests in 10 minutes'
            )
            logger.warning(f"Flagged rapid requests: {ip_address} ({request_count} in 10 min)")


@shared_task
def auto_block_suspicious_ips():
    """
    Automatically block IPs that have multiple suspicious flags
    """
    logger.info("Starting auto-block task for suspicious IPs")
    
    # Find IPs with multiple suspicious activities in the last 24 hours
    suspicious_ips = SuspiciousIP.objects.filter(
        detected_at__gte=timezone.now() - timedelta(hours=24)
    ).values('ip_address').annotate(
        flag_count=Count('id')
    ).filter(flag_count__gte=3)  # 3 or more flags
    
    blocked_count = 0
    for ip_data in suspicious_ips:
        ip_address = ip_data['ip_address']
        flag_count = ip_data['flag_count']
        
        # Check if IP is already blocked
        if not BlockedIP.objects.filter(ip_address=ip_address).exists():
            # Get the reasons for blocking
            reasons = SuspiciousIP.objects.filter(
                ip_address=ip_address,
                detected_at__gte=timezone.now() - timedelta(hours=24)
            ).values_list('reason', flat=True)
            
            combined_reason = f"Auto-blocked: {flag_count} suspicious activities - " + "; ".join(reasons[:3])
            
            BlockedIP.objects.create(
                ip_address=ip_address,
                reason=combined_reason
            )
            
            blocked_count += 1
            logger.warning(f"Auto-blocked suspicious IP: {ip_address} ({flag_count} flags)")
    
    logger.info(f"Auto-block task completed. Blocked {blocked_count} IPs")
    return f"Auto-blocked {blocked_count} suspicious IPs"


@shared_task
def cleanup_old_logs():
    """
    Clean up old request logs to prevent database bloat
    Keep logs for 30 days
    """
    logger.info("Starting log cleanup task")
    
    cutoff_date = timezone.now() - timedelta(days=30)
    
    # Delete old request logs
    deleted_logs, _ = RequestLog.objects.filter(timestamp__lt=cutoff_date).delete()
    
    # Delete old suspicious IP entries that have been reviewed
    deleted_suspicious, _ = SuspiciousIP.objects.filter(
        detected_at__lt=cutoff_date,
        is_reviewed=True
    ).delete()
    
    logger.info(f"Cleanup completed. Deleted {deleted_logs} request logs and {deleted_suspicious} suspicious IP entries")
    return f"Cleaned up {deleted_logs} logs and {deleted_suspicious} suspicious entries"