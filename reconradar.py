#!/usr/bin/env python3
"""
Recon Radar - Consolidated Web & GitHub Reconnaissance Tool
==============================================================
A single-file recon tool for authorized security testing / bug bounty
hunting. Combines: security header analysis, sensitive file exposure,
SSL/TLS checks, JS file secret-hunting, common misconfiguration ("low
hanging fruit") detection, and GitHub org secret-leak auditing.

⚠️  ETHICAL USE ONLY — READ BEFORE RUNNING  ⚠️
------------------------------------------------
Only run this against:
  1. A target you own, OR
  2. A target explicitly listed in-scope in an active bug bounty program
     (verify against the program's official scope page — do not guess
     domains/orgs), OR
  3. A target covered by a signed authorization/contract.

This tool performs read-only, non-destructive checks only. It does not
exploit anything, brute-force credentials, or send exploit payloads. It
never prints raw secret values to the terminal or any file — only the
location (file/URL/repo) so you can manually verify and remediate.

Unauthorized scanning of systems you don't have permission to test may
violate computer misuse laws in your jurisdiction, regardless of intent.

Usage:
    python webrecon.py example.com
    python webrecon.py https://example.com --github-org my-org
    python webrecon.py example.com --output report.txt
"""

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

try:
    from tqdm import tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False

    def tqdm(iterable, **kwargs):
        """Fallback no-op wrapper if tqdm isn't installed."""
        return iterable

# ─────────────────────────────────────────────────────────────────────────
# Terminal output helpers
# ─────────────────────────────────────────────────────────────────────────

class C:
    """ANSI colors for terminal output."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


LOG_LINES = []  # collected for optional --output text file
JSON_FINDINGS = {"target": None, "started": None, "finished": None, "sections": {}}
_CURRENT_SECTION = [None]  # mutable holder so section() can update the active section name
_SEEN_FINDINGS = set()  # dedup so identical findings aren't printed twice


def log(msg: str, to_file: bool = True):
    print(msg)
    if to_file:
        clean = re.sub(r"\033\[[0-9;]*m", "", msg)
        LOG_LINES.append(clean)


def info(msg):
    log(f"{C.BLUE}[*]{C.END} {msg}")


def found(msg):
    clean = re.sub(r"\033\[[0-9;]*m", "", msg)
    if clean in _SEEN_FINDINGS:
        return  # already printed this exact finding, skip
    _SEEN_FINDINGS.add(clean)
    log(f"{C.RED}[+]{C.END} {msg}")
    sec = _CURRENT_SECTION[0] or "general"
    JSON_FINDINGS["sections"].setdefault(sec, []).append({"type": "finding", "message": clean})


def ok(msg):
    log(f"{C.GREEN}[-]{C.END} {msg}")


def warn(msg):
    log(f"{C.YELLOW}[!]{C.END} {msg}")


def section(title):
    log("")
    log(f"{C.BOLD}>> {title}{C.END}")
    _CURRENT_SECTION[0] = title
    JSON_FINDINGS["sections"].setdefault(title, [])


# ─────────────────────────────────────────────────────────────────────────
# Plugin Registry
# ─────────────────────────────────────────────────────────────────────────
# Checks register themselves with @register_plugin instead of being
# hardcoded into main(). This makes it easy to add a new check without
# touching the main scan loop: just write a function that takes
# (full_url, hostname, args) and decorate it.
#
# Example — adding a brand new check:
#
#     @register_plugin(name="my_check", default_enabled=True)
#     def my_check(full_url, hostname, args):
#         section("My Custom Check")
#         ...
#         found("Something interesting")

PLUGINS = []  # list of dicts: {name, func, default_enabled}


def register_plugin(name: str, default_enabled: bool = True):
    """Decorator that registers a scan function as a plugin."""
    def decorator(func):
        PLUGINS.append({"name": name, "func": func, "default_enabled": default_enabled})
        return func
    return decorator


def run_plugins(full_url, hostname, args, extra_context=None):
    """
    Runs all registered, enabled plugins in registration order.
    `args.skip` (a set of plugin names) lets the CLI disable specific ones.
    `extra_context` is an optional dict merged into kwargs for plugins
    that need extra data (e.g. sitemap_urls for JS scanning).
    """
    skip = getattr(args, "skip_plugins", None) or set()
    extra_context = extra_context or {}

    for plugin in PLUGINS:
        if plugin["name"] in skip:
            continue
        if not plugin["default_enabled"] and plugin["name"] not in getattr(args, "enable_plugins", set()):
            continue
        try:
            plugin["func"](full_url, hostname, args, **extra_context.get(plugin["name"], {}))
        except TypeError:
            # plugin doesn't accept extra kwargs — call with just the base signature
            plugin["func"](full_url, hostname, args)


# ─────────────────────────────────────────────────────────────────────────
# 1. Security Headers
# ─────────────────────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("High", "Forces HTTPS, mitigates SSL-stripping/downgrade attacks."),
    "Content-Security-Policy": ("High", "Restricts script/style sources, mitigates XSS."),
    "X-Frame-Options": ("Medium", "Prevents clickjacking via iframe embedding."),
    "X-Content-Type-Options": ("Medium", "Prevents MIME-sniffing based XSS."),
    "Referrer-Policy": ("Low", "Controls referrer info leaked to other sites."),
    "Permissions-Policy": ("Low", "Restricts browser feature access (camera, geo, etc.)."),
}

INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def check_headers(url: str, timeout: int = 10):
    section("Security Headers")
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        warn(f"Request failed: {e}")
        return

    for header, (severity, desc) in SECURITY_HEADERS.items():
        if header in resp.headers:
            ok(f"{header}: set ({resp.headers[header][:50]})")
        else:
            found(f"Missing header: {header} [{severity}] — {desc}")

    for header in INFO_LEAK_HEADERS:
        if header in resp.headers:
            found(f"Info-leaking header: {header}: {resp.headers[header]}")

    set_cookie = resp.headers.get("Set-Cookie", "")
    if set_cookie:
        if "Secure" not in set_cookie:
            found("Cookie missing 'Secure' flag")
        if "HttpOnly" not in set_cookie:
            found("Cookie missing 'HttpOnly' flag")
        if "SameSite" not in set_cookie:
            found("Cookie missing 'SameSite' attribute")


# ─────────────────────────────────────────────────────────────────────────
# 2. Exposed Sensitive Files
# ─────────────────────────────────────────────────────────────────────────

SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config", ".env", ".env.local", ".env.production",
    "config.php.bak", "wp-config.php.bak", "backup.zip", "backup.sql",
    "database.sql", ".DS_Store", ".htpasswd", "docker-compose.yml",
    "id_rsa", "phpinfo.php", "server-status", "swagger.json", "swagger-ui.html",
    "actuator/env", "actuator/health", "debug/vars", ".vscode/sftp.json",
]


def check_exposed_files(base_url: str, timeout: int = 8, max_workers: int = 8):
    section("Exposed Sensitive Files")
    base_url = base_url.rstrip("/")
    any_found = False

    def _check_path(path):
        target = f"{base_url}/{path}"
        try:
            resp = requests.get(target, timeout=timeout, allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                return (path, target, len(resp.content))
        except requests.exceptions.RequestException:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = tqdm(executor.map(_check_path, SENSITIVE_PATHS), total=len(SENSITIVE_PATHS),
                        desc="Checking paths", unit="path", disable=not _HAS_TQDM)
        for result in results:
            if result:
                path, target, size = result
                found(f"{path} — HTTP 200 ({size} bytes) — {target}")
                any_found = True

    if not any_found:
        ok("No commonly-exposed sensitive files detected")


# ─────────────────────────────────────────────────────────────────────────
# 3. SSL/TLS Certificate Check
# ─────────────────────────────────────────────────────────────────────────

def check_ssl(hostname: str, port: int = 443, timeout: int = 8):
    section("SSL/TLS Certificate")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.now(timezone.utc).replace(tzinfo=None)).days
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "Unknown")

        if days_left < 0:
            found(f"Certificate EXPIRED {abs(days_left)} days ago (issuer: {issuer})")
        elif days_left <= 30:
            found(f"Certificate expiring soon: {days_left} days left (issuer: {issuer})")
        else:
            ok(f"Certificate valid, {days_left} days remaining (issuer: {issuer})")
    except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError, OSError) as e:
        warn(f"Could not check SSL: {e}")


# ─────────────────────────────────────────────────────────────────────────
# 4. robots.txt / sitemap.xml Discovery
# ─────────────────────────────────────────────────────────────────────────

def check_discovery(base_url: str, timeout: int = 8):
    section("robots.txt / sitemap.xml Discovery")
    base_url = base_url.rstrip("/")
    sitemap_urls = []

    try:
        resp = requests.get(f"{base_url}/robots.txt", timeout=timeout)
        if resp.status_code == 200:
            disallowed = re.findall(r"Disallow:\s*(\S+)", resp.text, flags=re.IGNORECASE)
            if disallowed:
                for path in disallowed[:20]:
                    found(f"robots.txt Disallow (may hint at hidden path): {path}")
            else:
                ok("robots.txt found, no Disallow rules")
        else:
            ok("No robots.txt found")
    except requests.exceptions.RequestException:
        ok("No robots.txt found")

    try:
        resp = requests.get(f"{base_url}/sitemap.xml", timeout=timeout)
        if resp.status_code == 200:
            sitemap_urls = re.findall(r"<loc>(.*?)</loc>", resp.text)
            found(f"sitemap.xml found with {len(sitemap_urls)} URLs")
    except requests.exceptions.RequestException:
        pass

    return sitemap_urls


# ─────────────────────────────────────────────────────────────────────────
# 4c. Technology / Framework / CMS Detection (passive, header + HTML based)
# ─────────────────────────────────────────────────────────────────────────

TECH_SIGNATURES = {
    # header-based: {header_name: {value_substring: tech_name}}
    "headers": {
        "Server": {
            "nginx": "Nginx",
            "apache": "Apache HTTP Server",
            "cloudflare": "Cloudflare",
            "microsoft-iis": "Microsoft IIS",
            "litespeed": "LiteSpeed",
        },
        "X-Powered-By": {
            "php": "PHP",
            "asp.net": "ASP.NET",
            "express": "Express.js",
            "next.js": "Next.js",
        },
        "X-Generator": {
            "drupal": "Drupal",
            "wordpress": "WordPress",
        },
        "X-AspNet-Version": {"": "ASP.NET"},
        "X-Drupal-Cache": {"": "Drupal"},
        "X-Varnish": {"": "Varnish Cache"},
    },
    # HTML body substring -> tech name
    "html_markers": {
        'name="generator" content="WordPress': "WordPress",
        'name="generator" content="Drupal': "Drupal",
        'name="generator" content="Joomla': "Joomla",
        "wp-content/": "WordPress",
        "wp-includes/": "WordPress",
        "/sites/default/files/": "Drupal",
        "cdn.shopify.com": "Shopify",
        "__NEXT_DATA__": "Next.js",
        "ng-version=": "Angular",
        "data-reactroot": "React",
        "__NUXT__": "Nuxt.js",
        "id=\"__next\"": "Next.js",
        "vue.js": "Vue.js",
        "laravel_session": "Laravel",
        "csrfmiddlewaretoken": "Django",
        "X-Magento": "Magento",
    },
    # cookie name -> tech name
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java (JSP/Servlet)",
        "ASP.NET_SessionId": "ASP.NET",
        "laravel_session": "Laravel",
        "django_language": "Django",
        "wordpress_logged_in": "WordPress",
    },
}


def detect_technologies(base_url: str, timeout: int = 10):
    """
    Passive technology fingerprinting — reuses a single GET request's
    response headers, cookies, and HTML body to identify frameworks,
    CMS platforms, and server software. No extra requests are sent
    beyond the one normal page load.
    """
    section("Technology Detection")
    try:
        resp = requests.get(base_url, timeout=timeout)
    except requests.exceptions.RequestException as e:
        warn(f"Could not fetch page for tech detection: {e}")
        return

    detected = set()

    for header_name, value_map in TECH_SIGNATURES["headers"].items():
        header_val = resp.headers.get(header_name)
        if header_val is None:
            continue
        for substring, tech in value_map.items():
            if substring == "" or substring.lower() in header_val.lower():
                detected.add(f"{tech} (via {header_name} header)")

    body = resp.text
    for marker, tech in TECH_SIGNATURES["html_markers"].items():
        if marker.lower() in body.lower():
            detected.add(f"{tech} (via page content)")

    cookie_names = resp.cookies.keys() if hasattr(resp.cookies, "keys") else []
    for cookie_name in cookie_names:
        for marker, tech in TECH_SIGNATURES["cookies"].items():
            if marker.lower() in cookie_name.lower():
                detected.add(f"{tech} (via cookie: {cookie_name})")

    if detected:
        for tech in sorted(detected):
            found(f"Detected: {tech}")
    else:
        ok("No known technology signatures detected (may be using an unlisted stack, or obfuscated headers)")


# ─────────────────────────────────────────────────────────────────────────
# 4b. Deep Crawl via Katana (optional — for finding JS files beyond homepage)
# ─────────────────────────────────────────────────────────────────────────

def deep_crawl_katana(base_url: str, depth: int = 3, limit: int = 500, timeout: int = 600):
    """
    Wraps the Katana crawler (https://github.com/projectdiscovery/katana) if
    installed, to discover URLs (including JS files) across the whole site
    rather than just the homepage. Returns a list of discovered URLs, or an
    empty list if Katana isn't installed or the crawl fails.
    """
    section("Deep Crawl (Katana)")
    if not shutil.which("katana"):
        warn("Katana not installed — skipping deep crawl. Install: "
             "go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return []

    info(f"Crawling {base_url} (depth={depth}, limit={limit})... this may take a while")
    try:
        proc = subprocess.run(
            ["katana", "-u", base_url, "-d", str(depth), "-jc", "-silent",
             "-timeout", "10", "-c", "10"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        warn(f"Katana crawl timed out after {timeout}s — using whatever it found so far")
        return []
    except Exception as e:
        warn(f"Katana crawl failed: {e}")
        return []

    urls = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    urls = urls[:limit]
    found(f"Katana discovered {len(urls)} URL(s) (capped at {limit})")
    return urls


# ─────────────────────────────────────────────────────────────────────────
# 5. JS File Discovery + Hardcoded Secret / Sensitive Endpoint Detection
# ─────────────────────────────────────────────────────────────────────────

# Regex patterns for common hardcoded secrets in JS bundles.
# Values are NEVER printed in full — only a redacted preview + line context.
JS_SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase DB URL": r"[a-z0-9-]+\.firebaseio\.com",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,48}",
    "Stripe Key": r"(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Generic Bearer Token": r"[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Private Key Header": r"-----BEGIN (RSA|EC|OPENSSH|DSA)? ?PRIVATE KEY-----",
    "Generic API Key Assignment": r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]",
    "Generic Secret Assignment": r"['\"]?(secret|token|passwd|password)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
}

# Endpoints/paths sometimes disclosed inside JS bundles that hint at
# internal or unauthenticated attack surface worth manual follow-up.
JS_SENSITIVE_ENDPOINT_PATTERNS = {
    "Internal/Admin endpoint": r"https?://[^\s'\"]*(admin|internal|staging|dev)[^\s'\"]*",
    "Cloud storage bucket": r"https?://[^\s'\"]*\.s3\.amazonaws\.com[^\s'\"]*",
    "Debug/verbose flag": r"debug\s*[:=]\s*true",
    "Hardcoded localhost/internal IP": r"https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s'\"]*",
    "GraphQL endpoint": r"https?://[^\s'\"]*/graphql[^\s'\"]*",
}


def _extract_js_links(html: str, base_url: str) -> list:
    links = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, flags=re.IGNORECASE)
    return list({urljoin(base_url, link) for link in links})


def _redact(match_text: str) -> str:
    """Shows only first/last few chars so the finding is verifiable without leaking the full secret."""
    if len(match_text) <= 12:
        return match_text[:3] + "..." + match_text[-2:]
    return match_text[:6] + "..." + match_text[-4:]


def scan_js_files(base_url: str, timeout: int = 10, max_files: int = 40, extra_pages: list = None):
    section("JS File Secret & Sensitive Endpoint Scan")
    pages_to_check = [base_url] + (extra_pages or [])
    js_links = set()

    for page_url in pages_to_check:
        try:
            resp = requests.get(page_url, timeout=timeout)
            js_links.update(_extract_js_links(resp.text, page_url))
        except requests.exceptions.RequestException:
            continue

    js_links = list(js_links)
    if not js_links:
        ok("No <script src=...> JS files found on the checked page(s)")
        return

    info(f"Discovered {len(js_links)} JS file(s) across {len(pages_to_check)} page(s), scanning up to {max_files}...")
    any_found = False

    def _fetch_js(js_url):
        try:
            r = requests.get(js_url, timeout=timeout)
            if r.status_code == 200:
                return (js_url, r.text)
        except requests.exceptions.RequestException:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        fetched = [r for r in tqdm(executor.map(_fetch_js, js_links[:max_files]),
                                     total=min(len(js_links), max_files),
                                     desc="Scanning JS files", unit="file", disable=not _HAS_TQDM) if r]

    for js_url, content in fetched:
        for label, pattern in JS_SECRET_PATTERNS.items():
            for m in re.finditer(pattern, content):
                found(f"[{label}] {_redact(m.group(0))}  —  {js_url}")
                any_found = True

        for label, pattern in JS_SENSITIVE_ENDPOINT_PATTERNS.items():
            seen = set()
            for m in re.finditer(pattern, content, flags=re.IGNORECASE):
                match_val = m.group(0)
                if match_val in seen:
                    continue
                seen.add(match_val)
                found(f"[{label}] {match_val[:80]}  —  {js_url}")
                any_found = True

    if not any_found:
        ok("No hardcoded secrets or sensitive endpoints detected in scanned JS files")


# ─────────────────────────────────────────────────────────────────────────
# 6. Low-Hanging-Fruit Misconfiguration Checks
# ─────────────────────────────────────────────────────────────────────────

def check_low_hanging_fruit(base_url: str, timeout: int = 8):
    section("Low-Hanging-Fruit Misconfigurations")
    base_url = base_url.rstrip("/")
    any_found = False

    # CORS misconfiguration: reflects arbitrary Origin or uses wildcard with credentials
    try:
        headers = {"Origin": "https://evil-test-origin.example"}
        resp = requests.get(base_url, headers=headers, timeout=timeout)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            found("CORS misconfig: wildcard origin + credentials allowed (high impact)")
            any_found = True
        elif acao == headers["Origin"]:
            found("CORS misconfig: arbitrary Origin reflected back in ACAO header")
            any_found = True
        elif acao == "*":
            found("CORS: Access-Control-Allow-Origin is '*' (check if sensitive data is served here)")
            any_found = True
    except requests.exceptions.RequestException:
        pass

    # Directory listing enabled
    common_dirs = ["images/", "uploads/", "assets/", "static/", "backup/", "files/"]
    for d in common_dirs:
        try:
            resp = requests.get(f"{base_url}/{d}", timeout=timeout)
            if resp.status_code == 200 and ("Index of /" in resp.text or "<title>Directory listing" in resp.text):
                found(f"Directory listing enabled: /{d}")
                any_found = True
        except requests.exceptions.RequestException:
            continue

    # Verbose error / stack trace disclosure via a harmless malformed request
    try:
        resp = requests.get(f"{base_url}/%00", timeout=timeout)
        body = resp.text.lower()
        stack_markers = ["stack trace", "traceback (most recent", "at java.", "microsoft ole db",
                         "unhandled exception", "fatal error:", "warning: include", "django traceback"]
        if any(marker in body for marker in stack_markers):
            found("Verbose error page / stack trace disclosed on malformed request")
            any_found = True
    except requests.exceptions.RequestException:
        pass

    # Dangerous HTTP methods enabled (PUT/DELETE/TRACE)
    try:
        resp = requests.options(base_url, timeout=timeout)
        allow = resp.headers.get("Allow", "")
        risky = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
        if risky:
            found(f"Potentially risky HTTP methods enabled: {', '.join(risky)}")
            any_found = True
    except requests.exceptions.RequestException:
        pass

    # Common exposed API docs / admin panels (quick check, not exhaustive)
    common_panels = [
        "swagger-ui/", "api-docs", "graphql", "actuator", "wp-admin/", "phpmyadmin/",
        ".well-known/security.txt",
    ]
    for panel in common_panels:
        try:
            resp = requests.get(f"{base_url}/{panel}", timeout=timeout, allow_redirects=False)
            if resp.status_code == 200:
                found(f"Publicly accessible: /{panel}")
                any_found = True
        except requests.exceptions.RequestException:
            continue

    if not any_found:
        ok("No common low-hanging-fruit misconfigurations detected")


# ─────────────────────────────────────────────────────────────────────────
# 7. GitHub Org Secret-Leak Audit (Code Search dorks + optional TruffleHog)
# ─────────────────────────────────────────────────────────────────────────

GITHUB_API = "https://api.github.com/search/code"

DORK_CATEGORIES = {
    "Credential & Secret Leakage": [
        '"aws_secret_access_key"', '"slack_token"', '"DATABASE_URL"',
        '"sendgrid_api_key"', '"client_secret"',
    ],
    "Internal Config & CI/CD": [
        'filename:.env', 'filename:docker-compose.yml', 'filename:sshd_config',
        '"service_account" extension:json',
    ],
    "Dev/Test & Staging Discovery": [
        '"test_api_key"', '"debug=true"', '"internal_use_only"',
    ],
    "Cloud Pivot Points": [
        '"private_key" extension:txt', 'filename:id_rsa', '"jdbc:mysql://"',
    ],
    "Cloud AI API Keys (Azure/OpenAI)": [
        '"api_key" "azure" "deployment_id" extension:json',
        '"api_key" "openai" extension:json',
        '"AZURE_OPENAI_API_KEY" extension:env',
        '"api-key" "azure" extension:yaml',
        '"api_key" "deployment_id" "endpoint" extension:json',
    ],
}


def _github_token():
    return os.environ.get("GITHUB_TOKEN")


def audit_github_org(org: str, pause: float = 2.0):
    section(f"GitHub Org Secret-Leak Audit: {org}")
    token = _github_token()
    if not token:
        warn("No GITHUB_TOKEN env var set — skipping GitHub Code Search dork audit.")
        warn("export GITHUB_TOKEN=ghp_xxxx  (classic PAT, no scopes needed for public code search)")
    else:
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3.text-match+json"}
        any_found = False
        for category, terms in DORK_CATEGORIES.items():
            for term in terms:
                query = f'org:"{org}" {term}'
                try:
                    resp = requests.get(GITHUB_API, headers=headers, params={"q": query, "per_page": 10}, timeout=10)
                    if resp.status_code == 200:
                        for item in resp.json().get("items", []):
                            found(f"[{category}] {item['repository']['full_name']} — {item['path']}  ({item['html_url']})")
                            any_found = True
                    elif resp.status_code == 403:
                        warn("Rate limited by GitHub Code Search — slowing down...")
                        time.sleep(10)
                except requests.exceptions.RequestException as e:
                    warn(f"Request failed for '{term}': {e}")
                time.sleep(pause)
        if not any_found:
            ok("No matches found via GitHub Code Search dorks")

    # Optional TruffleHog deep scan (full git history, verified-live detection)
    if not shutil.which("trufflehog"):
        info("TruffleHog not installed — skipping deep history scan. "
             "(https://github.com/trufflesecurity/trufflehog)")
        return

    info("Running TruffleHog full-history scan (this may take a while)...")
    try:
        proc = subprocess.run(
            ["trufflehog", "github", f"--org={org}", "--json", "--no-update"],
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        warn("TruffleHog scan timed out after 600s")
        return

    verified_count = 0
    unverified_count = 0
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta = record.get("SourceMetadata", {}).get("Data", {}).get("Github", {})
        repo = meta.get("repository", "unknown")
        file_ = meta.get("file", "unknown")
        detector = record.get("DetectorName", "unknown")
        if record.get("Verified"):
            found(f"🔴 VERIFIED LIVE SECRET [{detector}] {repo} — {file_}")
            verified_count += 1
        else:
            found(f"[unverified] [{detector}] {repo} — {file_}")
            unverified_count += 1

    if verified_count == 0 and unverified_count == 0:
        ok("TruffleHog: no secrets detected across full commit history")
    else:
        warn(f"TruffleHog summary: {verified_count} VERIFIED live secret(s), {unverified_count} unverified match(es)")


# ─────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────

def normalize_target(target: str):
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    return target, urlparse(target).netloc


# ─────────────────────────────────────────────────────────────────────────
# Subdomain Enumeration via crt.sh (Certificate Transparency logs)
# ─────────────────────────────────────────────────────────────────────────

def enumerate_subdomains_crtsh(root_domain: str, timeout: int = 15) -> list:
    """
    Queries crt.sh (public Certificate Transparency log search) for
    certificates issued for the domain, extracting subdomain names from
    the certificate SANs. Fully passive — sends zero requests to the
    target itself, only to crt.sh's public API.
    """
    section(f"Subdomain Enumeration (crt.sh): {root_domain}")
    url = f"https://crt.sh/?q=%25.{root_domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Recon-Radar/1.0"})
        resp.raise_for_status()
        data = resp.json()
    except (requests.exceptions.RequestException, ValueError) as e:
        warn(f"crt.sh query failed: {e}")
        return []

    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.splitlines():
            line = line.strip().lower()
            if line.startswith("*."):
                line = line[2:]
            if line.endswith(root_domain) and line != root_domain:
                subdomains.add(line)

    subdomains = sorted(subdomains)
    if subdomains:
        found(f"crt.sh found {len(subdomains)} unique subdomain(s)")
        for sub in subdomains[:50]:  # cap terminal output, full list still returned
            log(f"    {sub}")
        if len(subdomains) > 50:
            info(f"...and {len(subdomains) - 50} more (see --json-output for full list)")
    else:
        ok("No subdomains found via crt.sh")

    return subdomains


def enumerate_subdomains_external_tool(root_domain: str, tool: str = "subfinder", timeout: int = 300) -> list:
    """
    Optional wrapper for subfinder, assetfinder, or findomain if installed
    on the system. All three are passive-source subdomain tools (no active
    brute-forcing), which is why amass (much slower, does active DNS
    brute-forcing by default) isn't included here.
    Returns a list of discovered subdomains, or [] if the tool isn't found.
    """
    if not shutil.which(tool):
        info(f"{tool} not installed — skipping. (crt.sh results above still apply)")
        return []

    section(f"Subdomain Enumeration ({tool})")
    try:
        if tool == "subfinder":
            cmd = ["subfinder", "-d", root_domain, "-silent"]
        elif tool == "assetfinder":
            cmd = ["assetfinder", "--subs-only", root_domain]
        elif tool == "findomain":
            cmd = ["findomain", "-t", root_domain, "-q"]
        else:
            warn(f"Unknown tool: {tool}")
            return []

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        warn(f"{tool} timed out after {timeout}s")
        return []
    except Exception as e:
        warn(f"{tool} failed: {e}")
        return []

    subs = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if subs:
        found(f"{tool} found {len(subs)} subdomain(s)")
    else:
        ok(f"No additional subdomains found via {tool}")
    return subs


def check_liveness(url: str, retries: int = 3, timeout: int = 5) -> bool:
    """
    Quick liveness check before running the full scan on a target.
    Tries a HEAD request (falls back to GET if HEAD isn't allowed),
    retrying up to `retries` times with a short timeout each attempt.
    Returns True if the target responded at all (any status code),
    False if every attempt failed (DNS error, connection refused, timeout).
    """
    for attempt in range(1, retries + 1):
        try:
            resp = requests.head(url, timeout=timeout, allow_redirects=True)
            return True
        except requests.exceptions.RequestException:
            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True)
                return True
            except requests.exceptions.RequestException:
                if attempt < retries:
                    time.sleep(1)  # brief pause before retry
                continue
    return False


# ─────────────────────────────────────────────────────────────────────────
# Plugin registrations — thin wrappers so each check fits the standard
# (full_url, hostname, args) signature expected by run_plugins().
# ─────────────────────────────────────────────────────────────────────────

@register_plugin(name="headers")
def _plugin_headers(full_url, hostname, args):
    check_headers(full_url)


@register_plugin(name="tech_detection")
def _plugin_tech_detection(full_url, hostname, args):
    detect_technologies(full_url)


@register_plugin(name="exposed_files")
def _plugin_exposed_files(full_url, hostname, args):
    check_exposed_files(full_url)


@register_plugin(name="ssl")
def _plugin_ssl(full_url, hostname, args):
    check_ssl(hostname)


@register_plugin(name="low_hanging_fruit")
def _plugin_low_hanging_fruit(full_url, hostname, args):
    if not args.skip_fruit:
        check_low_hanging_fruit(full_url)


def main():
    parser = argparse.ArgumentParser(
        description="WebRecon — consolidated web & GitHub recon tool (authorized testing only).",
        epilog="Only scan targets you own or are explicitly authorized to test.",
    )
    parser.add_argument("target", nargs="?", default=None, help="Domain or URL to scan, e.g. example.com")
    parser.add_argument("--list", default=None, help="Path to a text file with one domain/subdomain per line — scans each in turn")
    parser.add_argument("--github-org", default=None, help="GitHub org to audit for leaked secrets (needs GITHUB_TOKEN)")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains via crt.sh (passive) before scanning")
    parser.add_argument("--subfinder", action="store_true", help="Also run subfinder if installed (needs --subdomains)")
    parser.add_argument("--assetfinder", action="store_true", help="Also run assetfinder if installed (needs --subdomains)")
    parser.add_argument("--findomain", action="store_true", help="Also run findomain if installed (needs --subdomains)")
    parser.add_argument("--subdomain-output", default=None, help="Save unique subdomains (crt.sh + tools) to this file")
    parser.add_argument("--output", default=None, help="Save all terminal findings to a text file")
    parser.add_argument("--json-output", default=None, help="Save all findings as structured JSON to this file")
    parser.add_argument("--skip-js", action="store_true", help="Skip JS file secret scanning")
    parser.add_argument("--skip-fruit", action="store_true", help="Skip low-hanging-fruit misconfig checks")
    parser.add_argument("--deep-crawl", action="store_true", help="Use Katana to crawl beyond homepage/sitemap for JS discovery (requires katana installed)")
    parser.add_argument("--crawl-depth", type=int, default=3, help="Katana crawl depth (default: 3)")
    parser.add_argument("--crawl-limit", type=int, default=500, help="Max URLs to keep from Katana crawl (default: 500)")
    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("Provide either a target domain or --list <file>")

    targets = []
    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        except FileNotFoundError:
            print(f"[!] File not found: {args.list}")
            sys.exit(1)
        info(f"Loaded {len(targets)} target(s) from {args.list}")
    else:
        targets = [args.target]

    for i, raw_target in enumerate(targets, 1):
        full_url, hostname = normalize_target(raw_target)
        JSON_FINDINGS["target"] = full_url

        log(f"\n{C.BOLD}WebRecon{C.END} — target {i}/{len(targets)}: {full_url}")

        info(f"Checking liveness ({full_url})...")
        if not check_liveness(full_url):
            warn(f"DEAD — no response after retries, skipping {full_url}")
            continue

        JSON_FINDINGS["started"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log(f"Started: {JSON_FINDINGS['started']}")
        warn("Only proceed if you own this target or have explicit authorization to test it.")

        if args.subdomains:
            root_domain = hostname.split(":")[0]
            if root_domain.startswith("www."):
                root_domain = root_domain[4:]

            all_subs = set()
            all_subs.update(enumerate_subdomains_crtsh(root_domain))
            if args.subfinder:
                all_subs.update(enumerate_subdomains_external_tool(root_domain, tool="subfinder"))
            if args.assetfinder:
                all_subs.update(enumerate_subdomains_external_tool(root_domain, tool="assetfinder"))
            if args.findomain:
                all_subs.update(enumerate_subdomains_external_tool(root_domain, tool="findomain"))

            if all_subs:
                section("Subdomain Enumeration Summary")
                found(f"{len(all_subs)} unique subdomain(s) across all sources")
                if args.subdomain_output:
                    with open(args.subdomain_output, "w", encoding="utf-8") as f:
                        f.write("\n".join(sorted(all_subs)) + "\n")
                    info(f"Unique subdomains saved to: {args.subdomain_output}")

        # Independent checks run via the plugin registry (see PLUGINS list) —
        # add a new one with @register_plugin instead of editing this loop.
        run_plugins(full_url, hostname, args)

        sitemap_urls = check_discovery(full_url)
        extra_pages = list(sitemap_urls[:10])
        if args.deep_crawl:
            crawled = deep_crawl_katana(full_url, depth=args.crawl_depth, limit=args.crawl_limit)
            extra_pages.extend(crawled)

        if not args.skip_js:
            scan_js_files(full_url, extra_pages=extra_pages)

        if args.github_org and i == 1:
            # only run the org-wide GitHub audit once, not per-subdomain
            audit_github_org(args.github_org)

    section("Scan Complete")
    JSON_FINDINGS["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    info(f"Finished: {JSON_FINDINGS['finished']}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(LOG_LINES))
        print(f"\n[+] Findings saved to: {args.output}")

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(JSON_FINDINGS, f, indent=2)
        print(f"[+] JSON findings saved to: {args.json_output}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
