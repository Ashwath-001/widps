#!/usr/bin/env python3
"""
WIDPS Honeypot Captive Portal
================================
Lightweight HTTP server that mimics a WiFi login page.
Captures any credentials attackers try to submit (for forensic evidence).
Also logs all HTTP requests to understand attacker behavior.

This does NOT connect attackers to the internet — it's purely deception.

Usage:
    sudo python3 honeypot/captive_portal.py

Serves on:
    - 192.168.66.1:80  (HTTP)
    - 192.168.67.1:80  (HTTP - eduroam_guest subnet)
    - 192.168.68.1:80  (HTTP - HP-Print subnet)
    - 192.168.69.1:80  (HTTP - DIRECT subnet)

All interactions are logged to /tmp/widps_honeypot_http.log
"""

import json
import os
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from datetime import datetime

LOG_FILE = "/tmp/widps_honeypot_http.log"
LISTEN_PORT = 80

# Track all interactions per IP
interaction_log: dict = {}


def log_event(event_type: str, client_ip: str, data: dict):
    """Log an event to the honeypot HTTP log file."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "type": event_type,
        "client_ip": client_ip,
        **data,
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

    # Also print for real-time monitoring
    print(f"[PORTAL] [{event_type}] {client_ip} — {data.get('path', data.get('detail', ''))}")


# ---------------------------------------------------------------------------
# HTML Templates — designed to look like legitimate captive portals
# ---------------------------------------------------------------------------
LOGIN_PAGE_FREEWIFI = """<!DOCTYPE html>
<html>
<head>
    <title>Free WiFi - Connect</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, sans-serif; background: #f0f2f5; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 60px auto; background: white; border-radius: 12px; padding: 40px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        h1 { color: #1a73e8; font-size: 24px; margin-bottom: 8px; }
        p { color: #666; font-size: 14px; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; font-size: 16px; }
        button { width: 100%; padding: 14px; background: #1a73e8; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; margin-top: 16px; }
        button:hover { background: #1557b0; }
        .footer { text-align: center; color: #999; font-size: 12px; margin-top: 20px; }
        .logo { text-align: center; margin-bottom: 20px; font-size: 32px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">📶</div>
        <h1>Free WiFi Access</h1>
        <p>Sign in with your email to get free internet access.</p>
        <form method="POST" action="/login">
            <input type="email" name="email" placeholder="Email address" required>
            <input type="password" name="password" placeholder="Password (optional)">
            <input type="hidden" name="honeypot_trap" value="freewifi">
            <button type="submit">Connect to Internet</button>
        </form>
        <div class="footer">
            <p>By connecting, you agree to our Terms of Service.</p>
            <p>© 2025 Campus Network Services</p>
        </div>
    </div>
</body>
</html>"""

LOGIN_PAGE_EDUROAM = """<!DOCTYPE html>
<html>
<head>
    <title>eduroam Guest Access</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, sans-serif; background: #1a237e; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 60px auto; background: white; border-radius: 12px; padding: 40px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        h1 { color: #1a237e; font-size: 22px; margin-bottom: 8px; }
        p { color: #666; font-size: 14px; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; font-size: 16px; }
        button { width: 100%; padding: 14px; background: #1a237e; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; margin-top: 16px; }
        .header { text-align: center; margin-bottom: 20px; }
        .header img { height: 40px; }
        .footer { text-align: center; color: #999; font-size: 11px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h2>🎓 eduroam</h2></div>
        <h1>Guest Network Login</h1>
        <p>Enter your institutional credentials to connect.</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="user@institution.edu" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="hidden" name="honeypot_trap" value="eduroam_guest">
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">
            <p>Managed by IT Services. Contact helpdesk@institution.edu for access issues.</p>
        </div>
    </div>
</body>
</html>"""

SUCCESS_PAGE = """<!DOCTYPE html>
<html>
<head><title>Connected</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
    body { font-family: sans-serif; text-align: center; padding: 60px 20px; background: #f0f2f5; }
    .check { font-size: 64px; margin-bottom: 20px; }
    h1 { color: #34a853; }
    p { color: #666; }
</style>
</head>
<body>
    <div class="check">✓</div>
    <h1>Connected!</h1>
    <p>You now have internet access. Enjoy browsing.</p>
    <p style="font-size: 12px; color: #999; margin-top: 40px;">Session expires in 24 hours.</p>
</body>
</html>"""


class HoneypotHandler(BaseHTTPRequestHandler):
    """HTTP request handler that captures all attacker interactions."""

    def log_message(self, format, *args):
        """Override to suppress default logging (we do our own)."""
        pass

    def do_GET(self):
        client_ip = self.client_address[0]

        # Log the request
        log_event("http_get", client_ip, {
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "host": self.headers.get("Host", ""),
            "referer": self.headers.get("Referer", ""),
        })

        # Detect special paths that reveal tool usage
        suspicious_paths = {
            "/robots.txt": "Web crawler/scanner",
            "/.env": "Environment file enumeration",
            "/wp-admin": "WordPress scanner",
            "/admin": "Admin panel enumeration",
            "/.git": "Git repository exposure check",
            "/phpinfo.php": "PHP info enumeration",
            "/actuator": "Spring Boot actuator probe",
            "/api": "API enumeration",
            "/.well-known": "Well-known path probe",
            "/config": "Configuration file probe",
        }

        for path_prefix, reason in suspicious_paths.items():
            if self.path.startswith(path_prefix):
                log_event("suspicious_path", client_ip, {
                    "path": self.path,
                    "reason": reason,
                    "user_agent": self.headers.get("User-Agent", ""),
                })
                break

        # Detect automated scanners via User-Agent
        ua = self.headers.get("User-Agent", "").lower()
        scanner_signatures = ["nmap", "nikto", "sqlmap", "dirbuster", "gobuster",
                            "wfuzz", "burp", "zap", "nuclei", "httpx", "curl", "wget",
                            "python-requests", "go-http-client", "masscan"]
        for sig in scanner_signatures:
            if sig in ua:
                log_event("scanner_detected", client_ip, {
                    "tool": sig,
                    "user_agent": self.headers.get("User-Agent", ""),
                    "path": self.path,
                })
                break

        # Captive portal detection responses
        captive_checks = [
            "/generate_204",          # Android
            "/hotspot-detect.html",   # Apple
            "/ncsi.txt",             # Windows
            "/check_network_status",  # Firefox
            "/connectivity-check",    # Generic
        ]

        if self.path in captive_checks or "captive" in self.path.lower():
            # Respond as if we're a captive portal (triggers login page on device)
            self.send_response(302)
            self.send_header("Location", "http://192.168.66.1/login")
            self.end_headers()
            return

        # Determine which login page to show based on subnet
        host = self.headers.get("Host", "")
        if "192.168.67" in host or "eduroam" in self.path.lower():
            page = LOGIN_PAGE_EDUROAM
        else:
            page = LOGIN_PAGE_FREEWIFI

        # Serve login page
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(page.encode())

    def do_POST(self):
        client_ip = self.client_address[0]

        # Read POST body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(min(content_length, 4096)).decode("utf-8", errors="replace")

        # Parse form data
        params = parse_qs(body)
        clean_params = {k: v[0] if v else "" for k, v in params.items()}

        # LOG CREDENTIAL SUBMISSION — this is forensic evidence
        log_event("credential_submission", client_ip, {
            "path": self.path,
            "form_data": clean_params,
            "user_agent": self.headers.get("User-Agent", ""),
            "content_type": self.headers.get("Content-Type", ""),
            "honeypot_ssid": clean_params.get("honeypot_trap", "unknown"),
        })

        # If they submitted credentials, this is HIGH confidence malicious intent
        if "password" in clean_params and clean_params["password"]:
            log_event("password_captured", client_ip, {
                "detail": "Attacker submitted credentials to honeypot portal",
                "username_field": clean_params.get("email", clean_params.get("username", "")),
                "password_length": len(clean_params.get("password", "")),
            })

        # Respond with success page (keep them engaged)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(SUCCESS_PAGE)))
        self.end_headers()
        self.wfile.write(SUCCESS_PAGE.encode())

    def do_HEAD(self):
        """Handle HEAD requests (connectivity checks)."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()


def run_server(bind_addr: str, port: int):
    """Run HTTP server on a specific address."""
    try:
        server = HTTPServer((bind_addr, port), HoneypotHandler)
        print(f"[PORTAL] Listening on {bind_addr}:{port}")
        server.serve_forever()
    except OSError as e:
        print(f"[PORTAL] Cannot bind {bind_addr}:{port}: {e}", file=sys.stderr)


def main():
    print("=" * 60)
    print(" WIDPS Honeypot Captive Portal")
    print("=" * 60)
    print(f" Log file: {LOG_FILE}")
    print()

    # Ensure log file exists
    os.makedirs(os.path.dirname(LOG_FILE) if os.path.dirname(LOG_FILE) else ".", exist_ok=True)

    # Start servers on each honeypot subnet
    bind_addresses = [
        "192.168.66.1",  # FreeWiFi
        "192.168.67.1",  # eduroam_guest
        "192.168.68.1",  # HP-Print-Setup
        "192.168.69.1",  # DIRECT-wifi
    ]

    threads = []
    for addr in bind_addresses:
        t = threading.Thread(target=run_server, args=(addr, LISTEN_PORT), daemon=True)
        t.start()
        threads.append(t)

    # Also listen on 0.0.0.0 as fallback
    print(f"[PORTAL] Captive portal active on {len(bind_addresses)} subnets")
    print("[PORTAL] Press Ctrl+C to stop")
    print()

    try:
        # Main server on primary address (blocks)
        run_server("0.0.0.0", 8080)  # Backup port for testing without root
    except KeyboardInterrupt:
        print("\n[PORTAL] Shutting down...")


if __name__ == "__main__":
    main()
