#!/usr/bin/env python3
"""
Deterministic Ed25519 key generator
Copyright 2025 Jaka Polesnik

Licensed under Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)
https://creativecommons.org/licenses/by-nc/4.0/
"""

import hashlib
import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from pathlib import Path

def seed_from_string(seed_str: str) -> bytes:
    """Generate 32-byte seed from input string"""
    if not seed_str:
        raise ValueError("Seed string cannot be empty")
    return hashlib.sha256(seed_str.encode()).digest()

def generate_ed25519_key(seed: bytes, key_file: str, password: str = None):
    """Generate and save Ed25519 key pair from seed"""
    # Ensure seed is exactly 32 bytes (Ed25519 requirement)
    if len(seed) != 32:
        raise ValueError("Seed must be 32 bytes for Ed25519")
    
    # Create private key from seed
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key (with encryption if password provided)
    encryption = (serialization.BestAvailableEncryption(password.encode()) 
                 if password else serialization.NoEncryption())
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=encryption
    )
    
    # Serialize public key in OpenSSH format
    public_openssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    # Create the keys directory
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)

    # Save keys
    (keys_dir / key_file).write_bytes(private_pem)
    (keys_dir / (key_file + '.pub')).write_bytes(public_openssh)
    
    print(f"Private key saved to: {key_file}")
    print(f"Public key saved to: {key_file}.pub")

if __name__ == "__main__":
    # Get seed input (with verification)
    seed_input = getpass("Enter your seed string: ").strip()
    seed_input_repeat = getpass("Repeat your seed string: ").strip()
    
    if seed_input != seed_input_repeat:
        print("Error: Seed strings do not match.")
        sys.exit(1)
    
    if not seed_input:
        print("Error: Seed string cannot be empty.")
        sys.exit(1)
    if seed_input == seed_input_repeat:
        print("Seed strings match. Proceeding...")
    else:
        print("Unexpected error with seed input.")
        sys.exit(1)
    
    
    # Get password (optional)
    cert_password = getpass("Enter certificate password (leave empty for no password): ")
    cert_password_repeat = getpass("Repeat certificate password: ")
    
    if cert_password != cert_password_repeat:
        print("Error: Passwords do not match.")
        sys.exit(1)
    if cert_password == "":
        cert_password = None
    if cert_password is not None and cert_password == cert_password_repeat:
        print("Passwords match. Proceeding...")
    else:
        print("Unexpected error with password input.")
        sys.exit(1)
    
    # Get output filename
    key_file = input("Enter output key file name (default: id_ed25519): ").strip()
    if not key_file:
        key_file = "id_ed25519"
    
    # Generate and save keys
    try:
        seed = seed_from_string(seed_input)
        generate_ed25519_key(seed, key_file, cert_password if cert_password else None)
        print("Key generation successful!")
        
    except Exception as e:
        print(f"Error generating keys: {e}")
        sys.exit(1)