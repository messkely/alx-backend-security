from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """Model to store request logs with IP, timestamp, path, and geolocation data"""
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    path = models.CharField(max_length=500)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        db_table = 'request_logs'
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"


class BlockedIP(models.Model):
    """Model to store blocked IP addresses"""
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    reason = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'blocked_ips'
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'
    
    def __str__(self):
        return f"Blocked: {self.ip_address}"


class SuspiciousIP(models.Model):
    """Model to store suspicious IP addresses flagged by anomaly detection"""
    ip_address = models.GenericIPAddressField()
    reason = models.CharField(max_length=500)
    detected_at = models.DateTimeField(default=timezone.now)
    is_reviewed = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'suspicious_ips'
        ordering = ['-detected_at']
        unique_together = ['ip_address', 'reason', 'detected_at']
    
    def __str__(self):
        return f"Suspicious: {self.ip_address} - {self.reason}"