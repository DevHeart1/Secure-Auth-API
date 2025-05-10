import logging
import json
from django.utils import timezone
import re
import uuid
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

# Configure logger
logger = logging.getLogger('authentication.security')

class SecurityLoggingMiddleware:
    """
    Middleware to log authentication and security-related events
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Log authentication attempts and security-related events
        if request.path.startswith('/api/v1/auth/'):
            self._log_auth_event(request, response)

        return response

    def _log_auth_event(self, request, response):
        """Log authentication events"""
        event_data = {
            'timestamp': timezone.now().isoformat(),
            'ip_address': self._get_client_ip(request),
            'path': request.path,
            'method': request.method,
            'status_code': response.status_code,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        }

        # Add username for login attempts (without logging the password)
        if request.path.endswith('/login/') and request.method == 'POST':
            try:
                body_data = json.loads(request.body.decode('utf-8'))
                if 'email' in body_data:
                    event_data['email'] = body_data['email']
                    event_data['event_type'] = 'login_attempt'
                    if response.status_code == 200:
                        event_data['result'] = 'success'
                    else:
                        event_data['result'] = 'failure'
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        # For password reset attempts
        elif 'password_reset' in request.path and request.method == 'POST':
            event_data['event_type'] = 'password_reset_request'

        # For registration attempts
        elif request.path.endswith('/register/') and request.method == 'POST':
            event_data['event_type'] = 'registration'
            if response.status_code == 201:  # Created
                try:
                    body_data = json.loads(request.body.decode('utf-8'))
                    if 'email' in body_data:
                        event_data['email'] = body_data['email']
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        # Log with appropriate level based on status code
        if response.status_code >= 400:
            logger.warning(json.dumps(event_data))
        else:
            logger.info(json.dumps(event_data))

    def _get_client_ip(self, request):
        """Get client IP address from request headers"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware that adds security headers to all responses.
    """
    
    def __init__(self, get_response=None):
        self.get_response = get_response
        # One-time configuration and initialization on startup
        self.csp_nonce_length = getattr(settings, 'CSP_NONCE_LENGTH', 16)
        self.csp_report_uri = getattr(settings, 'CSP_REPORT_URI', None)
        self.xss_protection = getattr(settings, 'XSS_PROTECTION', '1; mode=block')
        self.content_type_options = getattr(settings, 'CONTENT_TYPE_OPTIONS', 'nosniff')
        self.frame_options = getattr(settings, 'X_FRAME_OPTIONS', 'DENY')
        self.hsts_seconds = getattr(settings, 'HSTS_SECONDS', 31536000)  # 1 year
        self.hsts_include_subdomains = getattr(settings, 'HSTS_INCLUDE_SUBDOMAINS', True)
        self.hsts_preload = getattr(settings, 'HSTS_PRELOAD', False)
        self.referrer_policy = getattr(settings, 'REFERRER_POLICY', 'strict-origin-when-cross-origin')
        self.permissions_policy = getattr(settings, 'PERMISSIONS_POLICY', 
                                            'accelerometer=(), camera=(), geolocation=(), gyroscope=(), ' 
                                            'magnetometer=(), microphone=(), payment=(), usb=()')
        
        # Cache report-only setting to avoid settings lookup on each request
        self.csp_report_only = getattr(settings, 'CSP_REPORT_ONLY', False)
    
    def _get_csp_nonce(self):
        """Generate a random nonce for Content-Security-Policy"""
        return uuid.uuid4().hex[:self.csp_nonce_length]
    
    def _build_csp_header(self, request):
        """Build the Content-Security-Policy header value"""
        # Default restrictive policy
        csp_directives = {
            'default-src': "'self'",
            'script-src': "'self'",
            'style-src': "'self'",
            'img-src': "'self' data:",
            'font-src': "'self'",
            'connect-src': "'self'",
            'frame-src': "'none'",
            'object-src': "'none'",
            'base-uri': "'self'",
            'form-action': "'self'",
            'frame-ancestors': "'none'",
            'upgrade-insecure-requests': '',
        }
        
        # Generate nonce for inline scripts (if needed)
        nonce = self._get_csp_nonce()
        request.csp_nonce = nonce
        
        # Add nonce to script-src directive
        if "'self'" in csp_directives['script-src']:
            csp_directives['script-src'] = f"{csp_directives['script-src']} 'nonce-{nonce}'"
        else:
            csp_directives['script-src'] = f"'self' 'nonce-{nonce}'"
        
        # Add report-uri if configured
        if self.csp_report_uri:
            csp_directives['report-uri'] = self.csp_report_uri
        
        # Generate full header value
        csp_header_value = '; '.join([
            f"{directive} {value}" if value else directive
            for directive, value in csp_directives.items()
        ])
        
        return csp_header_value
            
    def process_response(self, request, response):
        """
        Add security headers to the response.
        """
        # Content-Security-Policy
        csp_header_value = self._build_csp_header(request)
        header_name = 'Content-Security-Policy-Report-Only' if self.csp_report_only else 'Content-Security-Policy'
        response[header_name] = csp_header_value
        
        # X-XSS-Protection
        response['X-XSS-Protection'] = self.xss_protection
        
        # X-Content-Type-Options
        response['X-Content-Type-Options'] = self.content_type_options
        
        # X-Frame-Options
        response['X-Frame-Options'] = self.frame_options
        
        # Strict-Transport-Security
        hsts_header_parts = [f"max-age={self.hsts_seconds}"]
        if self.hsts_include_subdomains:
            hsts_header_parts.append("includeSubDomains")
        if self.hsts_preload:
            hsts_header_parts.append("preload")
        response['Strict-Transport-Security'] = "; ".join(hsts_header_parts)
        
        # Referrer-Policy
        response['Referrer-Policy'] = self.referrer_policy
        
        # Permissions-Policy (formerly Feature-Policy)
        response['Permissions-Policy'] = self.permissions_policy
        
        return response

class SecurityMonitoringMiddleware(MiddlewareMixin):
    """
    Middleware that monitors for potential security issues in requests.
    """
    
    def __init__(self, get_response=None):
        self.get_response = get_response
        # Common SQL injection patterns
        self.sql_patterns = [
            r'(\%27)|(\')|(\-\-)|(\%23)|(#)',
            r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))',
            r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))',
            r'((\%27)|(\'))union',
        ]
        self.sql_pattern_compiled = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_patterns]
        
        # Common XSS patterns
        self.xss_patterns = [
            r'<[^\w<>]*(?:[^<>\'"\s]*:)?[^\w<>]*(?:\W*s\W*c\W*r\W*i\W*p\W*t|\W*f\W*o\W*r\W*m|\W*s\W*t\W*y\W*l\W*e|\W*b\W*a\W*s\W*e|\W*i\W*m\W*g)',
            r'(?:j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:|d\s*a\s*t\s*a\s*:)',
            r'(?:o\s*n\w+\s*=)',
        ]
        self.xss_pattern_compiled = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]
    
    def process_request(self, request):
        """
        Check request for potential security issues.
        """
        # Skip checking for static file requests
        if request.path.startswith((settings.STATIC_URL or '/static/', settings.MEDIA_URL or '/media/')):
            return None
        
        self._check_request_for_attacks(request)
        return None
    
    def _check_request_for_attacks(self, request):
        """Check the request for common attack patterns"""
        # Get request data to check
        check_data = {}
        
        # Check query parameters
        if request.GET:
            check_data.update({f"GET:{key}": value for key, value in request.GET.items()})
        
        # Check POST data
        if request.POST and getattr(request, '_body', None) is None:  # Avoid checking POST if raw body is used
            # Filter out sensitive fields
            post_data = {k: '***' if k.lower() in {'password', 'token', 'key', 'secret'} else v 
                         for k, v in request.POST.items()}
            check_data.update({f"POST:{key}": value for key, value in post_data.items()})
        
        # Check path
        check_data["PATH"] = request.path
        
        # Check for SQL injection
        for key, value in check_data.items():
            if isinstance(value, str):
                for pattern in self.sql_pattern_compiled:
                    if pattern.search(value):
                        self._log_security_event(request, 'sql_injection', key, value)
                        break
        
        # Check for XSS
        for key, value in check_data.items():
            if isinstance(value, str):
                for pattern in self.xss_pattern_compiled:
                    if pattern.search(value):
                        self._log_security_event(request, 'xss', key, value)
                        break
    
    def _log_security_event(self, request, attack_type, param, value):
        """Log detected security events"""
        # Get client IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        # Sanitize the value for logging (remove actual payloads)
        if len(value) > 50:
            value = f"{value[:50]}... [truncated]"
        
        log_data = {
            'type': attack_type,
            'path': request.path,
            'method': request.method,
            'param': param,
            'value': value,  # Be careful about logging potentially malicious content
            'ip': ip,
            'user': request.user.email if hasattr(request, 'user') and request.user.is_authenticated else 'anonymous',
            'user_agent': request.META.get('HTTP_USER_AGENT', 'unknown'),
        }
        
        logger.warning(f"Potential {attack_type.upper()} attack detected: {log_data}")
        
        # In the future, you might want to add blocking logic here or increment
        # a rate limit counter for suspicious IPs