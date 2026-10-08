#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗ █████╗  ██████╗██╗  ██╗███████╗██████╗  ██████╗██████╗ ║
║  ██╔════╝██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔════╝██╔══██╗║
║  ██║     ███████║██║     █████╔╝ █████╗  ██████╔╝██║     ██████╔╝║
║  ██║     ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔═══╝ ██║     ██╔══██╗║
║  ╚██████╗██║  ██║╚██████╗██║  ██╗███████╗██║     ╚██████╗██║  ██║║
║   ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝╚═╝  ╚═╝║
║                                                                  ║
║   Web Cache Deception Scanner v2.0                               ║
║   Detect cache-based information disclosure vulnerabilities      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

Usage Examples:
    # Basic scan with cookies:
    python3 cache_decept.py -u https://target.com/profile -ck "session=abc123"
    
    # Scan from file:
    python3 cache_decept.py -f urls.txt -ck "session=abc123" -o report.html
    
    # With rate limit (1 request per second):
    python3 cache_decept.py -f urls.txt -ck "session=abc" -rl 1
    
    # With custom paths:
    python3 cache_decept.py -u https://target.com -p my-account -ck "..."
    
    # With keyword detection:
    python3 cache_decept.py -u https://target.com/profile -ck "..." -k "Welcome John"
    
    # Test with Unkeyed Headers (Cache Poisoning combo):
    python3 cache_decept.py -u https://target.com/profile -ck "..." --headers

Author: Your GitHub Username
License: MIT
GitHub:  https://github.com/YOUR_USERNAME/cache-decept
"""

import argparse
import base64
import hashlib
import json
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress SSL warnings (for testing purposes only!)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════════

BANNER = """
╔═══════════════════════════════════════════════════════════╗
║          CacheDecept v2.0 — Web Cache Deception           ║
║       Automated WCD Scanner for Bug Bounty Hunters        ║
╚═══════════════════════════════════════════════════════════╝
"""

VERSION = "2.0.0"
AUTHOR = "Your GitHub Username"

# ══════════════════════════════════════════════════════════════════
#  DEFAULT CONFIGURATION — All values overridable via CLI flags!
# ══════════════════════════════════════════════════════════════════

class Config:
    """Central configuration — all values overridable via CLI"""

    # ─── Rate Limiting & Speed ───
    RATE_LIMIT = 0              # Requests per second (0 = no limit)
    THREADS = 5                 # Concurrent workers
    TIMEOUT = 10                # Per-request timeout (seconds)
    RATE_LIMIT_PAUSE = 60       # Seconds to wait on 429 (Too Many Requests)
    RATE_LIMIT_THRESHOLD = 3    # Consecutive 429s before pausing

    # ─── Authentication ───
    COOKIES = None              # Raw cookie string
    HTTP_AUTH = None            # Basic auth: user:pass
    BEARER_TOKEN = None         # Bearer token

    # ─── HTTP Headers ───
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    CUSTOM_HEADERS = {}         # Additional headers
    USE_UNKEYED_HEADERS = False # Test with X-Forwarded-*, etc.

    # ─── Output ───
    OUTPUT_FILE = None
    OUTPUT_HTML = False
    OUTPUT_JSON = False
    OUTPUT_TXT = False
    VERBOSE = False

    # ─── Scanning ───
    KNOWN_PATH = None           # User-specified path (skip auto-discovery)
    KEYWORD = None              # Keyword to find in poisoned response

    # ─── Detection Settings ───
    MAX_VARIANTS_PER_URL = 60   # Max variants to test per URL
    CONTENT_LENGTH_TOLERANCE = 50  # Bytes of difference considered "same"


# ══════════════════════════════════════════════════════════════════
#  SENSITIVE PATHS
# ══════════════════════════════════════════════════════════════════

SENSITIVE_PATHS = [
    "/account",
    "/profile",
    "/dashboard",
    "/settings",
    "/user",
    "/admin",
    "/private",
    "/my-account",
    "/user/profile",
    "/dashboard/image",
    "/dashboard/profile",
    "/account/user",
    "/address",
    "/account/settings",
    "/profile/edit",
    "/user/settings",
    "/admin/panel",
    "/private/files",
    "/my-account/orders",
    "/user/details",
    "/dashboard/reports",
    "/account/profile",
    "/account/info",
    "/profile/view",
    "/admin/settings",
    "/private/data",
    "/my-account/settings",
    "/user/account",
]

# ══════════════════════════════════════════════════════════════════
#  FILE EXTENSIONS
# ══════════════════════════════════════════════════════════════════

FILE_EXTENSIONS = [
    ".css", ".js", ".svg", ".asp", ".aspx", ".atom",
    ".bak", ".bin", ".cgi", ".csv", ".do", ".eot",
    ".gif", ".ico", ".jpg", ".jpeg", ".json", ".jsp",
    ".mp3", ".mp4", ".old", ".pdf", ".php", ".png",
    ".rss", ".tar.gz", ".tmp", ".ttf", ".txt",
    ".webm", ".woff", ".woff2", ".xml", ".zip", ".7z",
]

# Common extensions for quick testing (subset for faster scans)
QUICK_EXTENSIONS = [".css", ".js", ".png", ".jpg", ".json", ".svg"]

# ══════════════════════════════════════════════════════════════════
#  DELIMITERS & ENCODING
# ══════════════════════════════════════════════════════════════════

DELIMITERS = [
    "", ";", "~", "\\", ":", "//", "/", "..", ".", "_", "-",
    "@", "?", "=", "##", "!*", "!", "&", "$",
]

ENCODED_DELIMITERS = [
    "%5c", "%3d", "%2f", "%2e", "%26", "%23", "%20",
    "%0a", "%09", "%00",
]

# ══════════════════════════════════════════════════════════════════
#  UNKEYED HEADERS (Cache Poisoning combinations!)
# ══════════════════════════════════════════════════════════════════

UNKEYED_HEADERS = [
    {"X-Original-URL": "/admin/"},
    {"X-Rewrite-URL": "/profile/"},
    {"X-Forwarded-Host": "cache-poison.attacker.com"},
    {"X-Forwarded-Path": "/static.css"},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Port": "8080"},
]

# ══════════════════════════════════════════════════════════════════
#  UTILITY CLASSES
# ══════════════════════════════════════════════════════════════════

class Color:
    """Terminal color codes"""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output"""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ""
        cls.MAGENTA = cls.CYAN = cls.WHITE = cls.RESET = cls.BOLD = ""


class RateLimiter:
    """Token-bucket rate limiter for respecting target's rate limits!"""

    def __init__(self, rate_limit: float):
        """
        Args:
            rate_limit: Requests per second (0 = no limit)
        """
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.lock = threading.Lock()
        self.min_interval = 1.0 / rate_limit if rate_limit > 0 else 0

    def wait(self):
        """Wait if necessary to respect the rate limit!"""
        with self.lock:
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
            self.last_request_time = time.time()


class HTTPClient:
    """HTTP client with retry logic and rate limiting!"""

    def __init__(self, config: Config):
        self.config = config
        self.rate_limiter = RateLimiter(config.RATE_LIMIT)
        self.session = requests.Session()
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Setup headers
        self.session.headers.update({'User-Agent': config.USER_AGENT})
        
        # Setup auth
        if config.HTTP_AUTH:
            user, password = config.HTTP_AUTH.split(':', 1)
            auth_str = base64.b64encode(f"{user}:{password}".encode()).decode()
            self.session.headers.update({'Authorization': f"Basic {auth_str}"})
        elif config.BEARER_TOKEN:
            self.session.headers.update({'Authorization': f"Bearer {config.BEARER_TOKEN}"})
        
        # Setup cookies
        if config.COOKIES:
            for cookie_pair in config.COOKIES.split(';'):
                if '=' in cookie_pair:
                    name, value = cookie_pair.strip().split('=', 1)
                    domain = None
                    # We'll set cookies per-request since domain varies
                    self.session.cookies.set(name, value)
        
        # Custom headers
        for key, value in config.CUSTOM_HEADERS.items():
            self.session.headers.update({key: value})

    def get(self, url: str, with_auth: bool = True, **kwargs) -> requests.Response:
        """Perform GET request with rate limiting!"""
        self.rate_limiter.wait()
        
        kwargs.setdefault('timeout', self.config.TIMEOUT)
        kwargs.setdefault('verify', False)
        kwargs.setdefault('allow_redirects', False)
        
        # Temporarily remove cookies if needed
        if not with_auth:
            saved_cookies = self.session.cookies.copy()
            self.session.cookies.clear()
        
        try:
            response = self.session.get(url, **kwargs)
        finally:
            # Restore cookies
            if not with_auth:
                self.session.cookies.update(saved_cookies)
        
        return response

    def get_no_auth(self, url: str, **kwargs) -> requests.Response:
        """GET request without authentication (no cookies)!"""
        return self.get(url, with_auth=False, **kwargs)


# ══════════════════════════════════════════════════════════════════
#  URL VARIANT GENERATOR
# ══════════════════════════════════════════════════════════════════

class URLVariantGenerator:
    """Generates all cache deception variants for a given URL!"""

    @staticmethod
    def generate(base_url: str, config: Config) -> dict:
        """Generate all test variants"""
        variants = {}
        base_url = base_url.rstrip('/')
        
        # Unique ID for cache busting
        unique_id = hashlib.md5(base_url.encode()).hexdigest()[:8]
        
        # Choose extensions based on verbosity
        extensions = FILE_EXTENSIONS if config.MAX_VARIANTS_PER_URL > 40 else QUICK_EXTENSIONS
        
        # ─── Technique 1: Simple Extension ───
        for ext in extensions:
            variants[f"{base_url}{ext}"] = f"extension{ext}"
        
        # ─── Technique 2: Extension + Query String ───
        for ext in QUICK_EXTENSIONS:
            variants[f"{base_url}{ext}?cb={unique_id}"] = f"ext_query{ext}"
        
        # ─── Technique 3: Matrix Parameters (Semicolon) ───
        for ext in ['.css', '.js', '.png', '.jpg', '.json']:
            variants[f"{base_url};cb={unique_id}{ext}"] = f"matrix{ext}"
        
        # ─── Technique 4: Encoded Delimiters ───
        for enc_delim in ENCODED_DELIMITERS[:5]:
            for ext in ['.css', '.js']:
                variants[f"{base_url}{enc_delim}{unique_id}{ext}"] = f"encoded{enc_delim}{ext}"
        
        # ─── Technique 5: Path Confusion ───
        variants[f"{base_url}//{unique_id}.css"] = "double_slash"
        variants[f"{base_url}/../{unique_id}.css"] = "traversal"
        variants[f"{base_url}/..%2f{unique_id}.css"] = "traversal_encoded"
        variants[f"{base_url}\\{unique_id}.css"] = "backslash"
        
        # ─── Technique 6: Extension + Slash ───
        for ext in ['.css', '.js', '.png']:
            variants[f"{base_url}{ext}/{unique_id}"] = f"ext_slash{ext}"
        
        # ─── Technique 7: Encoded Path Traversal ───
        for ext in ['.css', '.js']:
            variants[f"{base_url}/%2e%2e/assets/style{ext}"] = f"traversal_assets{ext}"
        
        # Limit variants if needed
        if len(variants) > config.MAX_VARIANTS_PER_URL:
            variants = dict(list(variants.items())[:config.MAX_VARIANTS_PER_URL])
        
        return variants


# ══════════════════════════════════════════════════════════════════
#  CACHE DETECTOR
# ══════════════════════════════════════════════════════════════════

class CacheDetector:
    """Analyzes response headers to determine cache status!"""

    CACHE_STATUS_HEADERS = [
        'x-cache',
        'cf-cache-status',
        'x-cache-status',
        'x-drupal-cache',
        'x-varnish',
        'age',
    ]

    NOT_CACHEABLE = ['private', 'no-store', 'no-cache']
    CACHEABLE = ['public', 'max-age=']

    @staticmethod
    def analyze(response) -> dict:
        """Analyze response for cache indicators"""
        result = {
            'cacheable': False,
            'cache_status': 'UNKNOWN',
            'cache_hit': False,
            'cache_control': response.headers.get('Cache-Control', ''),
            'age': response.headers.get('Age', ''),
            'detected_headers': {},
        }

        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # Check cache status headers
        for header in CacheDetector.CACHE_STATUS_HEADERS:
            if header in headers_lower:
                value = headers_lower[header]
                result['detected_headers'][header] = value
                
                if value.upper() == 'HIT':
                    result['cacheable'] = True
                    result['cache_status'] = 'HIT'
                    result['cache_hit'] = True
                    break
                elif value.upper() == 'MISS':
                    result['cacheable'] = True
                    result['cache_status'] = 'MISS'

        # Check Cache-Control
        cache_control = result['cache_control'].lower()
        if any(x in cache_control for x in CacheDetector.NOT_CACHEABLE):
            result['cacheable'] = False
            result['cache_status'] = 'NOT_CACHEABLE'
        elif any(x in cache_control for x in CacheDetector.CACHEABLE):
            result['cacheable'] = True
            if result['cache_status'] == 'UNKNOWN':
                result['cache_status'] = 'CACHEABLE'

        # Age header present = cached before
        if result['age'] and result['age'].isdigit():
            result['cacheable'] = True
            result['cache_status'] = 'HIT (Age)'

        return result


# ══════════════════════════════════════════════════════════════════
#  AUTH CHECKER
# ══════════════════════════════════════════════════════════════════

class AuthChecker:
    """Checks if a URL requires authentication (sensitive page)!"""

    LOGIN_KEYWORDS = [
        'sign in', 'log in', 'login', 'register',
        'sign up', 'forgot password', 'password',
        'email address', 'username',
    ]

    @staticmethod
    def check(client: HTTPClient, url: str, config: Config) -> dict:
        """
        Check if page is sensitive (requires auth)!
        Returns dict with 'sensitive' flag and 'reason'
        """
        try:
            response = client.get_no_auth(url)
            final_url = response.url
            content_lower = response.text.lower()

            # Check 1: Status code indicates auth required
            if response.status_code in [401, 403]:
                return {
                    'sensitive': True,
                    'reason': f"HTTP {response.status_code} — auth required",
                    'status': response.status_code
                }

            # Check 2: Redirected to login page
            if any(x in final_url.lower() for x in ['login', 'signin', 'auth', 'session']):
                return {
                    'sensitive': True,
                    'reason': f"Redirected to: {final_url}",
                    'status': response.status_code
                }

            # Check 3: Login keywords in content
            for keyword in AuthChecker.LOGIN_KEYWORDS:
                if keyword in content_lower:
                    return {
                        'sensitive': True,
                        'reason': f"Login page detected ('{keyword}')",
                        'status': response.status_code
                    }

            # No auth detected — might be public page
            return {
                'sensitive': False,
                'reason': "No auth barrier detected (might be public page)",
                'status': response.status_code
            }

        except requests.RequestException as e:
            return {
                'sensitive': False,
                'reason': f"Connection error: {e}",
                'status': 0
            }


# ══════════════════════════════════════════════════════════════════
#  WCD SCANNER — MAIN SCANNER LOGIC
# ══════════════════════════════════════════════════════════════════

class WCDScanner:
    """Main Web Cache Deception scanner!"""

    def __init__(self, config: Config):
        self.config = config
        self.client = HTTPClient(config)
        self.results = []
        self.scan_stats = {
            'urls_scanned': 0,
            'variants_tested': 0,
            'findings': 0,
            'confirmed': 0,
            'start_time': None,
            'end_time': None,
        }
        self.lock = threading.Lock()

    def scan_url(self, url: str) -> list:
        """Scan a single URL for Cache Deception!"""
        findings = []
        self.scan_stats['urls_scanned'] += 1
        
        if self.config.VERBOSE:
            print(f"{Color.CYAN}[SCAN]{Color.RESET} {url}")

        try:
            # ─── Step 1: Auth Pre-Check ───
            auth_check = AuthChecker.check(self.client, url, self.config)
            
            if not auth_check['sensitive']:
                if self.config.VERBOSE:
                    print(f"{Color.YELLOW}  [SKIP]{Color.RESET} {auth_check['reason']}")
                return findings
            
            if self.config.VERBOSE:
                print(f"{Color.GREEN}  [AUTH]{Color.RESET} {auth_check['reason']}")

            # ─── Step 2: Get Baseline (with auth) ───
            resp_baseline = self.client.get(url)
            baseline_hash = hashlib.md5(resp_baseline.content).hexdigest()
            baseline_length = len(resp_baseline.content)
            baseline_status = resp_baseline.status_code

            # ─── Step 3: Generate Variants ───
            variants = URLVariantGenerator.generate(url, self.config)
            
            if self.config.VERBOSE:
                print(f"{Color.CYAN}  [VARIANTS]{Color.RESET} {len(variants)} to test")

            # ─── Step 4: Test Each Variant ───
            for variant_url, variant_type in variants.items():
                self.scan_stats['variants_tested'] += 1
                
                try:
                    resp_variant = self.client.get(variant_url)
                    
                    # Analyze cache status
                    cache_info = CacheDetector.analyze(resp_variant)
                    
                    # Check if response matches baseline (server ignored extension!)
                    variant_hash = hashlib.md5(resp_variant.content).hexdigest()
                    variant_length = len(resp_variant.content)
                    
                    # Same content check (allowing small differences)
                    content_matches = (
                        variant_hash == baseline_hash or
                        (resp_variant.status_code == baseline_status and
                         abs(variant_length - baseline_length) < self.config.CONTENT_LENGTH_TOLERANCE)
                    )
                    
                    # Cacheable + same content = potential finding!
                    if content_matches and cache_info['cacheable'] and resp_variant.status_code == 200:
                        
                        # ─── Step 5: Verify Cache Deception (No-Auth) ───
                        resp_no_auth = self.client.get_no_auth(variant_url)
                        
                        # If we got content without auth = CONFIRMED Cache Deception!
                        if resp_no_auth.status_code == 200 and len(resp_no_auth.content) > 100:
                            
                            finding = {
                                'original_url': url,
                                'variant_url': variant_url,
                                'variant_type': variant_type,
                                'status': resp_variant.status_code,
                                'content_length': len(resp_variant.content),
                                'baseline_length': baseline_length,
                                'cache_status': cache_info['cache_status'],
                                'cache_hit': cache_info['cache_hit'],
                                'cache_control': cache_info['cache_control'],
                                'age': cache_info['age'],
                                'no_auth_status': resp_no_auth.status_code,
                                'no_auth_length': len(resp_no_auth.content),
                                'confirmed': True,
                                'timestamp': datetime.now().isoformat(),
                            }
                            
                            findings.append(finding)
                            self.scan_stats['findings'] += 1
                            self.scan_stats['confirmed'] += 1
                            
                            # Print finding immediately!
                            self._print_finding(finding)
                            
                            # Check keyword if specified
                            if self.config.KEYWORD:
                                if self.config.KEYWORD.lower() in resp_no_auth.text.lower():
                                    finding['keyword_found'] = True
                                    print(f"{Color.GREEN}  ✓ KEYWORD FOUND: {self.config.KEYWORD}{Color.RESET}")
                            continue
                    
                    # Rate limit check (429 detection)
                    if resp_variant.status_code == 429:
                        if self.config.VERBOSE:
                            print(f"{Color.YELLOW}  [RATE LIMIT]{Color.RESET} Pausing {self.config.RATE_LIMIT_PAUSE}s...")
                        time.sleep(self.config.RATE_LIMIT_PAUSE)
                
                except requests.RequestException as e:
                    if self.config.VERBOSE:
                        print(f"{Color.RED}  [ERROR]{Color.RESET} {variant_url}: {e}")
                    continue
            
            # ─── Step 6: Test Unkeyed Headers (if enabled) ───
            if self.config.USE_UNKEYED_HEADERS:
                findings.extend(self._test_unkeyed_headers(url))
        
        except requests.RequestException as e:
            if self.config.VERBOSE:
                print(f"{Color.RED}[FATAL]{Color.RESET} {url}: {e}")
        
        return findings

    def _test_unkeyed_headers(self, url: str) -> list:
        """Test with Unkeyed Headers (Cache Poisoning combo)!"""
        findings = []
        
        for header_dict in UNKEYED_HEADERS:
            try:
                # Save original headers
                original_headers = dict(self.client.session.headers)
                
                # Add unkeyed header
                self.client.session.headers.update(header_dict)
                
                # Make request
                resp = self.client.get(url)
                
                # Check reflection
                header_value = list(header_dict.values())[0]
                reflected = header_value in resp.text
                
                # Check cache
                cache_info = CacheDetector.analyze(resp)
                
                if reflected and cache_info['cacheable']:
                    finding = {
                        'original_url': url,
                        'variant_url': f"{url} + {list(header_dict.keys())[0]}: {header_value}",
                        'variant_type': f"unkeyed_header_{list(header_dict.keys())[0]}",
                        'status': resp.status_code,
                        'cache_status': cache_info['cache_status'],
                        'cache_control': cache_info['cache_control'],
                        'confirmed': True,
                        'timestamp': datetime.now().isoformat(),
                    }
                    findings.append(finding)
                    self._print_finding(finding)
                
                # Restore headers
                self.client.session.headers.clear()
                self.client.session.headers.update(original_headers)
                
            except requests.RequestException:
                continue
        
        return findings

    def _print_finding(self, finding: dict):
        """Print a finding immediately!"""
        print(f"\n{Color.RED}{Color.BOLD}{'💥' * 3} CACHE DECEPTION FOUND! {'💥' * 3}{Color.RESET}")
        print(f"{Color.RED}  URL:     {finding['original_url']}{Color.RESET}")
        print(f"{Color.YELLOW}  Variant: {finding['variant_url']}{Color.RESET}")
        print(f"{Color.CYAN}  Type:    {finding['variant_type']}{Color.RESET}")
        print(f"{Color.GREEN}  Cache:   {finding['cache_status']} | Control: {finding['cache_control']}{Color.RESET}")
        print(f"{Color.MAGENTA}  No-Auth: {finding['no_auth_status']} | Len: {finding['no_auth_length']}{Color.RESET}")
        print(f"{Color.RED}{'─' * 60}{Color.RESET}")

    def scan(self, urls: list):
        """Scan multiple URLs in parallel!"""
        self.scan_stats['start_time'] = datetime.now()
        
        print(f"{Color.CYAN}{BANNER}{Color.RESET}")
        print(f"{Color.BOLD}📡 URLs to scan: {len(urls)}{Color.RESET}")
        print(f"{Color.BOLD}⚡ Threads: {self.config.THREADS}{Color.RESET}")
        print(f"{Color.BOLD}⏱️  Rate Limit: {self.config.RATE_LIMIT if self.config.RATE_LIMIT > 0 else 'Unlimited'} req/s{Color.RESET}")
        print(f"{Color.BOLD}🔑 Keyword: {self.config.KEYWORD or 'None'}{Color.RESET}")
        print(f"{Color.BOLD}🔒 Unkeyed Headers: {'Enabled' if self.config.USE_UNKEYED_HEADERS else 'Disabled'}{Color.RESET}")
        print(f"{'═' * 60}\n")

        with ThreadPoolExecutor(max_workers=self.config.THREADS) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    findings = future.result()
                    self.results.extend(findings)
                except Exception as e:
                    print(f"{Color.RED}[ERROR]{Color.RESET} {url}: {e}")
        
        self.scan_stats['end_time'] = datetime.now()
        
        # Final summary
        duration = (self.scan_stats['end_time'] - self.scan_stats['start_time']).total_seconds()
        
        print(f"\n{Color.BOLD}{'═' * 60}{Color.RESET}")
        print(f"{Color.BOLD}📊 SCAN SUMMARY{Color.RESET}")
        print(f"{'═' * 60}")
        print(f"  URLs Scanned:        {self.scan_stats['urls_scanned']}")
        print(f"  Variants Tested:     {self.scan_stats['variants_tested']}")
        print(f"  Total Findings:      {self.scan_stats['findings']}")
        print(f"  Confirmed Cache Deception: {Color.GREEN}{Color.BOLD}{self.scan_stats['confirmed']}{Color.RESET}")
        print(f"  Duration:            {duration:.2f} seconds")
        print(f"{'═' * 60}\n")


# ══════════════════════════════════════════════════════════════════
#  REPORTER — Save Results
# ══════════════════════════════════════════════════════════════════

class Reporter:
    """Save scan results to files!"""

    @staticmethod
    def save_txt(results: list, filename: str):
        """Save as plain text report"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("  Cache Deception Scan Report\n")
            f.write(f"  Date: {datetime.now().isoformat()}\n")
            f.write(f"  Total Findings: {len(results)}\n")
            f.write("=" * 60 + "\n\n")
            
            for idx, r in enumerate(results, 1):
                f.write(f"[{idx}] CACHE DECEPTION FOUND\n")
                f.write(f"    Original URL:    {r['original_url']}\n")
                f.write(f"    Variant URL:     {r['variant_url']}\n")
                f.write(f"    Type:            {r['variant_type']}\n")
                f.write(f"    Status:          {r['status']}\n")
                f.write(f"    Cache Status:    {r['cache_status']}\n")
                f.write(f"    Cache-Control:   {r['cache_control']}\n")
                f.write(f"    Age:             {r['age']}\n")
                f.write(f"    No-Auth Status:  {r['no_auth_status']}\n")
                f.write(f"    No-Auth Length:  {r['no_auth_length']}\n")
                f.write(f"    Confirmed:       {r['confirmed']}\n")
                f.write(f"    Timestamp:       {r['timestamp']}\n")
                f.write("-" * 60 + "\n")

    @staticmethod
    def save_json(results: list, filename: str):
        """Save as JSON report"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({
                'scan_date': datetime.now().isoformat(),
                'total_findings': len(results),
                'findings': results
            }, f, indent=2, ensure_ascii=False)

    @staticmethod
    def save_html(results: list, filename: str):
        """Save as HTML report (professional!)"""
        
        findings_html = ""
        for r in results:
            severity = "CRITICAL" if r.get('confirmed') else "HIGH"
            findings_html += f"""
            <div class="finding critical">
                <div class="finding-header">
                    <span class="badge severity">{severity}</span>
                    <span class="badge cache">{r['cache_status']}</span>
                </div>
                <h3>Original URL:</h3>
                <p class="url">{r['original_url']}</p>
                <h3>Poisoned Variant:</h3>
                <p class="url">{r['variant_url']}</p>
                <table>
                    <tr><th>Type</th><td>{r['variant_type']}</td></tr>
                    <tr><th>Status Code</th><td>{r['status']}</td></tr>
                    <tr><th>Cache-Control</th><td>{r['cache_control']}</td></tr>
                    <tr><th>X-Cache / Age</th><td>{r['age']}</td></tr>
                    <tr><th>No-Auth Status</th><td>{r['no_auth_status']}</td></tr>
                    <tr><th>Content Length (No-Auth)</th><td>{r['no_auth_length']} bytes</td></tr>
                </table>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Cache Deception Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #1e1e2e; color: #cdd6f4; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; background: #181825; padding: 30px; border-radius: 10px; }}
        h1 {{ color: #cba6f7; border-bottom: 3px solid #f38ba8; padding-bottom: 10px; }}
        .summary {{ background: #313244; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .finding {{ background: #313244; border-left: 5px solid #f38ba8; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .url {{ font-family: monospace; background: #11111b; padding: 8px; border-radius: 4px; word-break: break-all; color: #a6e3a1; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; margin-right: 5px; }}
        .badge.severity {{ background: #f38ba8; color: #1e1e2e; }}
        .badge.cache {{ background: #a6e3a1; color: #1e1e2e; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #45475a; }}
        th {{ background: #45475a; color: #cdd6f4; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 Cache Deception Scan Report</h1>
        <div class="summary">
            <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Total Findings:</strong> {len(results)}<br>
            <strong>Severity:</strong> {"CRITICAL" if results else "NONE"}
        </div>
        {findings_html}
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)


# ══════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ══════════════════════════════════════════════════════════════════

def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='CacheDecept v2.0 — Web Cache Deception Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{BANNER}
Examples:
  # Basic scan:
  python3 {sys.argv[0]} -u https://target.com/profile -ck "session=abc123"
  
  # Scan from file with rate limit (1 req/s):
  python3 {sys.argv[0]} -f urls.txt -ck "session=abc" -rl 1
  
  # With custom sensitive path:
  python3 {sys.argv[0]} -u https://target.com -p my-account -ck "..."
  
  # With keyword detection:
  python3 {sys.argv[0]} -u https://target.com/profile -ck "..." -k "Welcome John"
  
  # With Unkeyed Headers (Cache Poisoning):
  python3 {sys.argv[0]} -u https://target.com/profile -ck "..." --headers
  
  # Full featured:
  python3 {sys.argv[0]} -f urls.txt -ck "session=..." -rl 2 -t 10 --headers \\
    --html --json -o report -k "John" -v
        """
    )
    
    # ─── Input ───
    input_group = parser.add_argument_group('📥 Input Options')
    input_group.add_argument('-u', '--url', help='Single URL to test')
    input_group.add_argument('-f', '--file', help='File containing list of URLs (one per line)')
    input_group.add_argument('-p', '--path', help='Sensitive path to test (e.g., "my-account")')
    
    # ─── Authentication ───
    auth_group = parser.add_argument_group('🔐 Authentication Options')
    auth_group.add_argument('-ck', '--cookies', help='Cookies string (e.g., "session=abc; other=xyz")')
    auth_group.add_argument('--auth', help='HTTP Basic Auth (user:pass)')
    auth_group.add_argument('--token', help='Bearer token for Authorization header')
    
    # ─── Rate Limiting ───
    rate_group = parser.add_argument_group('⏱️  Rate Limiting Options')
    rate_group.add_argument('-rl', '--rate-limit', type=float, default=0,
                            help='Rate limit in requests/second (0 = unlimited)')
    rate_group.add_argument('-t', '--threads', type=int, default=5,
                            help='Number of concurrent threads (default: 5)')
    rate_group.add_argument('--timeout', type=int, default=10,
                            help='Request timeout in seconds (default: 10)')
    rate_group.add_argument('--rate-limit-pause', type=int, default=60,
                            help='Seconds to wait on 429 (default: 60)')
    
    # ─── Detection ───
    detect_group = parser.add_argument_group('🎯 Detection Options')
    detect_group.add_argument('-k', '--keyword', help='Keyword to search in poisoned response')
    detect_group.add_argument('-H', '--header', action='append',
                              help='Custom header (e.g., "X-Custom: value")')
    detect_group.add_argument('--headers', action='store_true',
                              help='Test with Unkeyed Headers (X-Forwarded-*, etc.)')
    detect_group.add_argument('--ua', help='Custom User-Agent')
    detect_group.add_argument('--max-variants', type=int, default=60,
                              help='Max variants per URL (default: 60)')
    detect_group.add_argument('--tolerance', type=int, default=50,
                              help='Content length tolerance for matching (default: 50)')
    
    # ─── Output ───
    output_group = parser.add_argument_group('📤 Output Options')
    output_group.add_argument('-o', '--output', help='Output file base name (without extension)')
    output_group.add_argument('--html', action='store_true', help='Save HTML report')
    output_group.add_argument('--json', action='store_true', help='Save JSON report')
    output_group.add_argument('--txt', action='store_true', help='Save TXT report')
    output_group.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    
    args = parser.parse_args()
    
    # Validate
    if not args.url and not args.file:
        parser.error("You must provide either -u or -f!")
    
    return args


# ══════════════════════════════════════════════════════════════════
#  MAIN FUNCTION
# ══════════════════════════════════════════════════════════════════

def main():
    args = parse_args()
    
    # Build config
    config = Config()
    config.RATE_LIMIT = args.rate_limit
    config.THREADS = args.threads
    config.TIMEOUT = args.timeout
    config.RATE_LIMIT_PAUSE = args.rate_limit_pause
    config.COOKIES = args.cookies
    config.HTTP_AUTH = args.auth
    config.BEARER_TOKEN = args.token
    config.KEYWORD = args.keyword
    config.VERBOSE = args.verbose
    config.OUTPUT_FILE = args.output
    config.OUTPUT_HTML = args.html
    config.OUTPUT_JSON = args.json
    config.OUTPUT_TXT = args.txt
    config.USE_UNKEYED_HEADERS = args.headers
    config.MAX_VARIANTS_PER_URL = args.max_variants
    config.CONTENT_LENGTH_TOLERANCE = args.tolerance
    
    if args.ua:
        config.USER_AGENT = args.ua
    
    # Custom headers
    if args.header:
        for h in args.header:
            if ':' in h:
                key, value = h.split(':', 1)
                config.CUSTOM_HEADERS[key.strip()] = value.strip()
    
    # Get URLs
    if args.url:
        urls = [args.url]
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        print("Error: No URLs provided!")
        sys.exit(1)
    
    # Disable colors if not TTY
    if not sys.stdout.isatty():
        Color.disable()
    
    # Start scanning!
    scanner = WCDScanner(config)
    scanner.scan(urls)
    
    # Save results
    if scanner.results and config.OUTPUT_FILE:
        base_name = config.OUTPUT_FILE.rsplit('.', 1)[0]
        
        if config.OUTPUT_HTML:
            Reporter.save_html(scanner.results, f"{base_name}.html")
            print(f"{Color.GREEN}[SAVED]{Color.RESET} HTML report: {base_name}.html")
        
        if config.OUTPUT_JSON:
            Reporter.save_json(scanner.results, f"{base_name}.json")
            print(f"{Color.GREEN}[SAVED]{Color.RESET} JSON report: {base_name}.json")
        
        if config.OUTPUT_TXT:
            Reporter.save_txt(scanner.results, f"{base_name}.txt")
            print(f"{Color.GREEN}[SAVED]{Color.RESET} TXT report: {base_name}.txt")
        
        # Default: save HTML if no format specified
        if not (config.OUTPUT_HTML or config.OUTPUT_JSON or config.OUTPUT_TXT):
            Reporter.save_html(scanner.results, f"{base_name}.html")
            print(f"{Color.GREEN}[SAVED]{Color.RESET} HTML report (default): {base_name}.html")
    
    print(f"\n{Color.CYAN}🏁 Scan complete!{Color.RESET}")


if __name__ == '__main__':
    main()