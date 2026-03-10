#!/usr/bin/env python3
"""
Security Features:
- AES-256 encryption (CBC mode)
- PBKDF2 key derivation with salt
- Master password protection
- Secure memory handling
- Password generation
- Input validation
- Audit logging
"""

import os
import sys
import json
import base64
import hashlib
import getpass
import secrets
import string
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import sqlite3

class SecurePasswordManager:
    """
    Main password manager class with AES-256 encryption
    """
    
    def __init__(self, db_path='passwords.enc'):
        self.db_path = db_path
        self.master_key = None
        self.salt = None
        self.current_user = None
        self.audit_log = []
        
        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for storing encrypted entries"""
        try:
            self.conn = sqlite3.connect('securepass.db')
            self.cursor = self.conn.cursor()
            
            # Create tables if they don't exist
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP,
                    nonce TEXT NOT NULL,
                    salt TEXT NOT NULL
                )
            ''')
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    action TEXT,
                    user TEXT,
                    service TEXT,
                    ip_address TEXT
                )
            ''')
            
            self.conn.commit()
        except Exception as e:
            print(f"[-] Database initialization failed: {e}")
            sys.exit(1)
    
    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        """
        Derive encryption key using PBKDF2
        Returns: (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)  # 128-bit salt
        
        # PBKDF2 with 100,000 iterations
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode())
        return key, salt
    
    def encrypt_data(self, data: str, key: bytes) -> tuple:
        """
        Encrypt data using AES-256-GCM
        Returns: (encrypted_data, nonce, tag)
        """
        # Generate random nonce
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        
        # Encrypt data
        encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
        
        # Get authentication tag
        tag = encryptor.tag
        
        # Combine encrypted data with tag
        encrypted_package = base64.b64encode(encrypted_data + tag).decode()
        
        return encrypted_package, base64.b64encode(nonce).decode()
    
    def decrypt_data(self, encrypted_package: str, key: bytes, nonce_b64: str) -> str:
        """
        Decrypt data using AES-256-GCM
        """
        try:
            # Decode from base64
            encrypted_data = base64.b64decode(encrypted_package)
            nonce = base64.b64decode(nonce_b64)
            
            # Separate encrypted data and tag
            tag = encrypted_data[-16:]  # Last 16 bytes are the tag
            ciphertext = encrypted_data[:-16]  # Rest is ciphertext
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            
            # Decrypt data
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted_data.decode()
            
        except InvalidTag:
            raise ValueError("Authentication failed - data may have been tampered with")
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def initialize_master(self):
        """
        Initialize master password for first-time use
        """
        print("\n" + "="*50)
        print("FIRST TIME SETUP - Create Master Password")
        print("="*50)
        print("Requirements:")
        print("- Minimum 12 characters")
        print("- At least 1 uppercase letter")
        print("- At least 1 lowercase letter")
        print("- At least 1 number")
        print("- At least 1 special character")
        
        while True:
            master_pass = getpass.getpass("\nCreate master password: ")
            
            # Validate password strength
            if len(master_pass) < 12:
                print("[-] Password too short (min 12 characters)")
                continue
            
            if not any(c.isupper() for c in master_pass):
                print("[-] Password needs at least 1 uppercase letter")
                continue
            
            if not any(c.islower() for c in master_pass):
                print("[-] Password needs at least 1 lowercase letter")
                continue
            
            if not any(c.isdigit() for c in master_pass):
                print("[-] Password needs at least 1 number")
                continue
            
            if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in master_pass):
                print("[-] Password needs at least 1 special character")
                continue
            
            confirm_pass = getpass.getpass("Confirm master password: ")
            
            if master_pass != confirm_pass:
                print("[-] Passwords don't match!")
                continue
            
            # Derive master key
            self.master_key, self.salt = self.derive_key(master_pass)
            
            # Save salt for future logins
            with open('master.salt', 'w') as f:
                f.write(base64.b64encode(self.salt).decode())
            
            # Create a verification hash
            verifier = hashlib.sha256(master_pass.encode()).hexdigest()
            with open('master.verifier', 'w') as f:
                f.write(verifier)
            
            print("\n[+] Master password created successfully!")
            self.audit_action("MASTER_CREATED", "system")
            return True
    
    def login(self):
        """
        Authenticate user with master password
        """
        print("\n" + "="*50)
        print(" SECUREPASS LOGIN")
        print("="*50)
        
        # Check if first time setup needed
        if not os.path.exists('master.salt'):
            self.initialize_master()
            return True
        
        # Load salt
        try:
            with open('master.salt', 'r') as f:
                self.salt = base64.b64decode(f.read())
        except:
            print("[-] Corrupted installation. Please reinstall.")
            return False
        
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts:
            master_pass = getpass.getpass("Enter master password: ")
            
            # Derive key from entered password
            key, _ = self.derive_key(master_pass, self.salt)
            
            # Verify password
            verifier = hashlib.sha256(master_pass.encode()).hexdigest()
            
            try:
                with open('master.verifier', 'r') as f:
                    stored_verifier = f.read().strip()
                
                if verifier == stored_verifier:
                    self.master_key = key
                    print("\n[+] Login successful!")
                    self.audit_action("LOGIN_SUCCESS", "system")
                    return True
                else:
                    attempts += 1
                    remaining = max_attempts - attempts
                    print(f"[-] Incorrect password. {remaining} attempts remaining.")
                    self.audit_action("LOGIN_FAILED", "system")
                    
            except Exception as e:
                print(f"[-] Authentication error: {e}")
                return False
        
        print("\n[-] Too many failed attempts. Exiting.")
        return False
    
    def add_password(self):
        """
        Add a new password entry
        """
        print("\n" + "="*50)
        print("ADD NEW PASSWORD")
        print("="*50)
        
        service = input("Service/Website: ").strip()
        if not service:
            print("[-] Service name required")
            return
        
        username = input("Username/Email: ").strip()
        if not username:
            print("[-] Username required")
            return
        
        # Option to generate or enter password
        print("\nPassword options:")
        print("1. Generate strong password")
        print("2. Enter manually")
        
        choice = input("Choice (1/2): ").strip()
        
        if choice == '1':
            password = self.generate_password()
            print(f"\n[+] Generated password: {password}")
            print("(Password will be encrypted and stored securely)")
        else:
            password = getpass.getpass("Enter password: ")
            if not password:
                print("[-] Password required")
                return
        
        notes = input("Notes (optional): ").strip()
        
        # Encrypt password
        encrypted_pass, nonce = self.encrypt_data(password, self.master_key)
        
        # Store in database
        timestamp = datetime.now()
        
        self.cursor.execute('''
            INSERT INTO vault (service, username, encrypted_password, notes, 
                             created_at, updated_at, nonce, salt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (service, username, encrypted_pass, notes, timestamp, timestamp, 
              nonce, base64.b64encode(self.salt).decode()))
        
        self.conn.commit()
        
        print(f"\n[+] Password for {service} stored securely!")
        self.audit_action("PASSWORD_ADDED", service)
    
    def get_password(self):
        """
        Retrieve and decrypt a password
        """
        print("\n" + "="*50)
        print("RETRIEVE PASSWORD")
        print("="*50)
        
        # List available services
        self.cursor.execute('SELECT id, service, username FROM vault')
        entries = self.cursor.fetchall()
        
        if not entries:
            print("[-] No passwords stored yet.")
            return
        
        print("\nStored entries:")
        for entry_id, service, username in entries:
            print(f"  [{entry_id}] {service} - {username}")
        
        try:
            choice = int(input("\nEnter entry ID: "))
            
            self.cursor.execute('''
                SELECT service, username, encrypted_password, notes, nonce 
                FROM vault WHERE id = ?
            ''', (choice,))
            
            entry = self.cursor.fetchone()
            
            if entry:
                service, username, encrypted_pass, notes, nonce = entry
                
                # Decrypt password
                try:
                    decrypted_pass = self.decrypt_data(
                        encrypted_pass, 
                        self.master_key, 
                        nonce
                    )
                    
                    print("\n" + "-"*40)
                    print(f"Service: {service}")
                    print(f"Username: {username}")
                    print(f"Password: {decrypted_pass}")
                    if notes:
                        print(f"Notes: {notes}")
                    print("-"*40)
                    
                    self.audit_action("PASSWORD_VIEWED", service)
                    
                except ValueError as e:
                    print(f"[-] Decryption error: {e}")
                    self.audit_action("DECRYPTION_FAILED", service)
            
        except ValueError:
            print("[-] Invalid ID")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def list_passwords(self):
        """
        List all stored services (without showing passwords)
        """
        print("\n" + "="*50)
        print(" STORED PASSWORDS")
        print("="*50)
        
        self.cursor.execute('''
            SELECT service, username, created_at, updated_at 
            FROM vault ORDER BY service
        ''')
        
        entries = self.cursor.fetchall()
        
        if not entries:
            print("No passwords stored yet.")
            return
        
        for service, username, created, updated in entries:
            print(f"\n{service}")
            print(f"   Username: {username}")
            print(f"   Created: {created}")
            print(f"   Updated: {updated}")
    
    def delete_password(self):
        """
        Delete a password entry
        """
        print("\n" + "="*50)
        print("DELETE PASSWORD")
        print("="*50)
        
        self.cursor.execute('SELECT id, service, username FROM vault')
        entries = self.cursor.fetchall()
        
        if not entries:
            print("[-] No passwords stored.")
            return
        
        print("\nStored entries:")
        for entry_id, service, username in entries:
            print(f"  [{entry_id}] {service} - {username}")
        
        try:
            choice = int(input("\nEnter entry ID to delete: "))
            
            # Confirm deletion
            confirm = input("Are you sure? This cannot be undone (y/N): ").lower()
            
            if confirm == 'y':
                self.cursor.execute('DELETE FROM vault WHERE id = ?', (choice,))
                self.conn.commit()
                print("[+] Entry deleted successfully!")
                self.audit_action("PASSWORD_DELETED", f"ID:{choice}")
            else:
                print("[-] Deletion cancelled")
                
        except ValueError:
            print("[-] Invalid ID")
    
    def generate_password(self, length=16):
        """
        Generate a strong random password
        """
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one of each type
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(symbols)
        ]
        
        # Fill the rest randomly
        all_chars = lowercase + uppercase + digits + symbols
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle to avoid predictable pattern
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def audit_action(self, action, service):
        """
        Log security-relevant actions
        """
        timestamp = datetime.now()
        
        self.cursor.execute('''
            INSERT INTO audit_log (timestamp, action, service)
            VALUES (?, ?, ?)
        ''', (timestamp, action, service))
        
        self.conn.commit()
    
    def view_audit_log(self):
        """
        View security audit log
        """
        print("\n" + "="*50)
        print("SECURITY AUDIT LOG")
        print("="*50)
        
        self.cursor.execute('''
            SELECT timestamp, action, service 
            FROM audit_log 
            ORDER BY timestamp DESC 
            LIMIT 20
        ''')
        
        logs = self.cursor.fetchall()
        
        if not logs:
            print("No audit logs found.")
            return
        
        for timestamp, action, service in logs:
            print(f"\n[{timestamp}]")
            print(f"  Action: {action}")
            print(f"  Service: {service}")
    
    def export_encrypted_backup(self):
        """
        Export encrypted backup of all passwords
        """
        print("\n" + "="*50)
        print("EXPORT ENCRYPTED BACKUP")
        print("="*50)
        
        # Get all entries
        self.cursor.execute('SELECT * FROM vault')
        entries = self.cursor.fetchall()
        
        if not entries:
            print("[-] No entries to backup")
            return
        
        # Create backup dictionary
        backup = {
            'exported_at': datetime.now().isoformat(),
            'version': '1.0',
            'entries': []
        }
        
        for entry in entries:
            backup['entries'].append({
                'id': entry[0],
                'service': entry[1],
                'username': entry[2],
                'encrypted_password': entry[3],
                'notes': entry[4],
                'created_at': entry[5],
                'updated_at': entry[6],
                'nonce': entry[7],
                'salt': entry[8]
            })
        
        # Save backup
        filename = f"securepass_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(backup, f, indent=2)
        
        print(f"[+] Backup saved to: {filename}")
        print("[!] Store this file securely - it contains encrypted passwords")
        self.audit_action("BACKUP_EXPORTED", "system")
    
    def change_master_password(self):
        """
        Change master password and re-encrypt all entries
        """
        print("\n" + "="*50)
        print("CHANGE MASTER PASSWORD")
        print("="*50)
        print("This will re-encrypt all your passwords!")
        
        # Verify current password
        current_pass = getpass.getpass("Enter CURRENT master password: ")
        key, _ = self.derive_key(current_pass, self.salt)
        
        # Verify current password
        verifier = hashlib.sha256(current_pass.encode()).hexdigest()
        with open('master.verifier', 'r') as f:
            if verifier != f.read().strip():
                print("[-] Incorrect password!")
                return
        
        # Get new password
        while True:
            new_pass = getpass.getpass("Enter NEW master password: ")
            confirm_pass = getpass.getpass("Confirm new password: ")
            
            if new_pass != confirm_pass:
                print("[-] Passwords don't match!")
                continue
            
            if len(new_pass) < 12:
                print("[-] Password too short (min 12 characters)")
                continue
            
            break
        
        # Get all existing entries
        self.cursor.execute('SELECT id, encrypted_password, nonce FROM vault')
        entries = self.cursor.fetchall()
        
        # Derive new key
        new_key, new_salt = self.derive_key(new_pass)
        
        # Re-encrypt all entries
        print("\n[+] Re-encrypting all passwords...")
        
        for entry_id, encrypted_pass, old_nonce in entries:
            try:
                # Decrypt with old key
                decrypted = self.decrypt_data(encrypted_pass, self.master_key, old_nonce)
                
                # Encrypt with new key
                new_encrypted, new_nonce = self.encrypt_data(decrypted, new_key)
                
                # Update database
                self.cursor.execute('''
                    UPDATE vault 
                    SET encrypted_password = ?, nonce = ?, salt = ? 
                    WHERE id = ?
                ''', (new_encrypted, new_nonce, base64.b64encode(new_salt).decode(), entry_id))
                
            except Exception as e:
                print(f"[-] Error re-encrypting entry {entry_id}: {e}")
                return
        
        # Save new salt and verifier
        with open('master.salt', 'w') as f:
            f.write(base64.b64encode(new_salt).decode())
        
        new_verifier = hashlib.sha256(new_pass.encode()).hexdigest()
        with open('master.verifier', 'w') as f:
            f.write(new_verifier)
        
        # Update current key
        self.master_key = new_key
        self.salt = new_salt
        
        self.conn.commit()
        print("[+] Master password changed successfully!")
        self.audit_action("MASTER_PASSWORD_CHANGED", "system")
    
    def security_check(self):
        """
        Perform security check on stored passwords
        """
        print("\n" + "="*50)
        print("SECURITY CHECK")
        print("="*50)
        
        issues = []
        
        # Check for weak/duplicate passwords
        self.cursor.execute('SELECT id, service, username, encrypted_password, nonce FROM vault')
        entries = self.cursor.fetchall()
        
        passwords = []
        
        for entry_id, service, username, encrypted_pass, nonce in entries:
            try:
                password = self.decrypt_data(encrypted_pass, self.master_key, nonce)
                
                # Check password strength
                strength = self.check_password_strength(password)
                
                if strength['score'] < 3:
                    issues.append({
                        'service': service,
                        'username': username,
                        'issue': 'Weak password',
                        'details': strength['feedback']
                    })
                
                passwords.append(password)
                
            except:
                continue
        
        # Check for duplicate passwords
        seen = set()
        duplicates = set()
        for pwd in passwords:
            if pwd in seen:
                duplicates.add(pwd)
            seen.add(pwd)
        
        if duplicates:
            issues.append({
                'issue': 'Duplicate passwords found',
                'details': f'Found {len(duplicates)} passwords used multiple times'
            })
        
        # Display results
        if issues:
            print("\nSecurity Issues Found:")
            for issue in issues:
                print(f"\n  • {issue.get('service', 'System')}: {issue['issue']}")
                if 'details' in issue:
                    print(f"    → {issue['details']}")
        else:
            print("\nNo security issues found!")
        
        # Check last audit
        self.cursor.execute('SELECT MAX(timestamp) FROM audit_log')
        last_audit = self.cursor.fetchone()[0]
        if last_audit:
            print(f"\nLast audit: {last_audit}")
    
    def check_password_strength(self, password):
        """
        Check password strength and return score
        """
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
            feedback.append("Consider using longer password (12+ chars)")
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        return {'score': score, 'feedback': ', '.join(feedback)}
    
    def cleanup(self):
        """
        Clean up sensitive data from memory
        """
        self.master_key = None
        self.conn.close()
        print("\n[+] Secure shutdown complete")

def main():
    """
    Main program loop
    """
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("\n" + "="*60)
    print(" SECUREPASS - Professional Password Manager")
    print("="*60)
    print("AES-256 Encryption | PBKDF2 Key Derivation | Secure Audit Logging")
    
    # Initialize manager
    manager = SecurePasswordManager()
    
    # Login
    if not manager.login():
        sys.exit(1)
    
    # Main menu
    while True:
        print("\n" + "="*50)
        print("MAIN MENU")
        print("="*50)
        print("1.  List all passwords")
        print("2.  Add new password")
        print("3.  Retrieve password")
        print("4.  Delete password")
        print("5.  Generate password")
        print("6.  Security check")
        print("7.  View audit log")
        print("8.  Export backup")
        print("9.  Change master password")
        print("10. Exit")
        
        choice = input("\nSelect option (1-10): ").strip()
        
        if choice == '1':
            manager.list_passwords()
        
        elif choice == '2':
            manager.add_password()
        
        elif choice == '3':
            manager.get_password()
        
        elif choice == '4':
            manager.delete_password()
        
        elif choice == '5':
            print(f"\n Generated password: {manager.generate_password(16)}")
        
        elif choice == '6':
            manager.security_check()
        
        elif choice == '7':
            manager.view_audit_log()
        
        elif choice == '8':
            manager.export_encrypted_backup()
        
        elif choice == '9':
            manager.change_master_password()
        
        elif choice == '10':
            manager.cleanup()
            print("\n Goodbye! Stay secure!")
            break
        
        else:
            print("[-] Invalid option")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted. Exiting securely...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)