from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import RequestLog, BlockedIP, SuspiciousIP


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'path', 'country', 'city', 'timestamp']
    list_filter = ['timestamp', 'country', 'city']
    search_fields = ['ip_address', 'path', 'country', 'city']
    ordering = ['-timestamp']
    readonly_fields = ['timestamp']
    
    # Add date hierarchy for better navigation
    date_hierarchy = 'timestamp'
    
    # Add custom actions
    actions = ['block_selected_ips']
    
    def block_selected_ips(self, request, queryset):
        """Admin action to block IPs from selected request logs"""
        blocked_count = 0
        for log in queryset:
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=log.ip_address,
                defaults={'reason': f'Blocked from admin - path: {log.path}'}
            )
            if created:
                blocked_count += 1
        
        self.message_user(
            request, 
            f'Successfully blocked {blocked_count} IP addresses.'
        )
    
    block_selected_ips.short_description = "Block selected IP addresses"
    
    def get_queryset(self, request):
        # Limit queryset to recent logs for performance
        qs = super().get_queryset(request)
        return qs.select_related().order_by('-timestamp')[:10000]


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'reason', 'created_at', 'get_recent_requests']
    list_filter = ['created_at']
    search_fields = ['ip_address', 'reason']
    ordering = ['-created_at']
    readonly_fields = ['created_at']
    
    def get_recent_requests(self, obj):
        """Show recent requests from this IP"""
        recent_count = RequestLog.objects.filter(ip_address=obj.ip_address).count()
        return f"{recent_count} requests"
    
    get_recent_requests.short_description = "Recent Requests"
    
    # Add custom actions
    actions = ['unblock_selected_ips']
    
    def unblock_selected_ips(self, request, queryset):
        """Admin action to unblock selected IPs"""
        count = queryset.count()
        queryset.delete()
        self.message_user(
            request,
            f'Successfully unblocked {count} IP addresses.'
        )
    
    unblock_selected_ips.short_description = "Unblock selected IP addresses"


@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address', 
        'reason', 
        'detected_at', 
        'is_reviewed',
        'get_block_status',
        'get_admin_actions'
    ]
    list_filter = ['detected_at', 'is_reviewed']
    search_fields = ['ip_address', 'reason']
    ordering = ['-detected_at']
    readonly_fields = ['detected_at']
    
    # Add filters for better organization
    list_editable = ['is_reviewed']
    
    def get_block_status(self, obj):
        """Check if IP is currently blocked"""
        is_blocked = BlockedIP.objects.filter(ip_address=obj.ip_address).exists()
        if is_blocked:
            return format_html(
                '<span style="color: red; font-weight: bold;">BLOCKED</span>'
            )
        return format_html(
            '<span style="color: green;">Not Blocked</span>'
        )
    
    get_block_status.short_description = "Block Status"
    
    def get_admin_actions(self, obj):
        """Show quick action buttons"""
        block_url = reverse('admin:ip_tracking_blockedip_add')
        view_logs_url = f"{reverse('admin:ip_tracking_requestlog_changelist')}?ip_address={obj.ip_address}"
        
        return format_html(
            '<a class="button" href="{}?ip_address={}" target="_blank">Block IP</a> '
            '<a class="button" href="{}" target="_blank">View Logs</a>',
            block_url,
            obj.ip_address,
            view_logs_url
        )
    
    get_admin_actions.short_description = "Actions"
    get_admin_actions.allow_tags = True
    
    # Add custom actions
    actions = ['mark_as_reviewed', 'block_suspicious_ips']
    
    def mark_as_reviewed(self, request, queryset):
        """Mark suspicious IPs as reviewed"""
        count = queryset.update(is_reviewed=True)
        self.message_user(
            request,
            f'Successfully marked {count} suspicious IPs as reviewed.'
        )
    
    mark_as_reviewed.short_description = "Mark as reviewed"
    
    def block_suspicious_ips(self, request, queryset):
        """Block selected suspicious IPs"""
        blocked_count = 0
        for suspicious_ip in queryset:
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=suspicious_ip.ip_address,
                defaults={
                    'reason': f'Auto-blocked from suspicious activity: {suspicious_ip.reason}'
                }
            )
            if created:
                blocked_count += 1
                suspicious_ip.is_reviewed = True
                suspicious_ip.save()
        
        self.message_user(
            request,
            f'Successfully blocked {blocked_count} suspicious IP addresses.'
        )
    
    block_suspicious_ips.short_description = "Block selected suspicious IPs"


# Customize admin site header and title
admin.site.site_header = "IP Tracking & Security Admin"
admin.site.site_title = "IP Tracking Admin"
admin.site.index_title = "Welcome to IP Tracking & Security Administration"