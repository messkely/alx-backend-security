from django.core.management.base import BaseCommand, CommandError
from django.core.cache import cache
from ip_tracking.models import BlockedIP
import ipaddress


class Command(BaseCommand):
    help = 'Block or unblock IP addresses'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            choices=['add', 'remove', 'list'],
            help='Action to perform: add, remove, or list blocked IPs'
        )
        parser.add_argument(
            '--ip',
            type=str,
            help='IP address to block or unblock'
        )
        parser.add_argument(
            '--reason',
            type=str,
            help='Reason for blocking the IP address'
        )
    
    def handle(self, *args, **options):
        action = options['action']
        
        if action == 'add':
            self.add_blocked_ip(options)
        elif action == 'remove':
            self.remove_blocked_ip(options)
        elif action == 'list':
            self.list_blocked_ips()
    
    def add_blocked_ip(self, options):
        ip_address = options.get('ip')
        reason = options.get('reason', 'No reason provided')
        
        if not ip_address:
            raise CommandError('IP address is required when adding a blocked IP')
        
        # Validate IP address
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            raise CommandError(f'Invalid IP address: {ip_address}')
        
        # Check if IP is already blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            self.stdout.write(
                self.style.WARNING(f'IP {ip_address} is already blocked')
            )
            return
        
        # Add IP to blocked list
        try:
            blocked_ip = BlockedIP.objects.create(
                ip_address=ip_address,
                reason=reason
            )
            
            # Clear cache for this IP
            cache_key = f"blocked_ip_{ip_address}"
            cache.delete(cache_key)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully blocked IP: {ip_address}\n'
                    f'Reason: {reason}'
                )
            )
        except Exception as e:
            raise CommandError(f'Failed to block IP {ip_address}: {e}')
    
    def remove_blocked_ip(self, options):
        ip_address = options.get('ip')
        
        if not ip_address:
            raise CommandError('IP address is required when removing a blocked IP')
        
        try:
            blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
            blocked_ip.delete()
            
            # Clear cache for this IP
            cache_key = f"blocked_ip_{ip_address}"
            cache.delete(cache_key)
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully unblocked IP: {ip_address}')
            )
        except BlockedIP.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(f'IP {ip_address} is not in the blocked list')
            )
        except Exception as e:
            raise CommandError(f'Failed to unblock IP {ip_address}: {e}')
    
    def list_blocked_ips(self):
        blocked_ips = BlockedIP.objects.all().order_by('-created_at')
        
        if not blocked_ips:
            self.stdout.write(self.style.WARNING('No blocked IPs found'))
            return
        
        self.stdout.write(self.style.SUCCESS('Blocked IP Addresses:'))
        self.stdout.write('-' * 80)
        
        for blocked_ip in blocked_ips:
            self.stdout.write(
                f'IP: {blocked_ip.ip_address}\n'
                f'Blocked on: {blocked_ip.created_at}\n'
                f'Reason: {blocked_ip.reason or "No reason provided"}\n'
                f'{"-" * 40}'
            )