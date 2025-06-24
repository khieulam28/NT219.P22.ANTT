import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sys
import random

# --- Configuration ---
HOST = '127.0.0.1'  
PORT = 8080
KEY_SIZE = 2048

POSSIBLE_COMMANDS = [
    b"ATTACK_NORTH",
    b"HOLD_POSITION",
    b"RETREAT_SOUTH",
    b"DEPLOY_ASSETS"
]

# --- Server Setup ---
def generate_rsa_keys():
    """Generates a new RSA key pair."""
    key = RSA.generate(KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def secure_rsa_encrypt(message, public_key_obj):
    """SECURE: Performs RSA encryption with PKCS1_OAEP padding."""
    cipher_rsa = PKCS1_OAEP.new(public_key_obj)
    ciphertext = cipher_rsa.encrypt(message)
    return ciphertext

def main():
    # 1. Generate RSA keys
    private_key_pem, public_key_pem = generate_rsa_keys()
    public_key = RSA.import_key(public_key_pem)
    
    # 2. Choose a secret command and encrypt it to create the target
    SECRET_COMMAND = random.choice(POSSIBLE_COMMANDS)
    TARGET_CIPHERTEXT = secure_rsa_encrypt(SECRET_COMMAND, public_key) # Using secure encryption
    
    print("--- SECURE RSA Server (with PKCS1_OAEP Padding) ---")
    print(f"[*] Generated a {KEY_SIZE}-bit RSA key pair.")
    print(f"[*] The secret command has been chosen and securely encrypted with PKCS1_OAEP.")
    print(f"[*] Secret Command (for verification): {SECRET_COMMAND.decode()}")
    print(f"[*] Target Ciphertext (Hex): {TARGET_CIPHERTEXT.hex()}")
    print("-" * 30)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Server listening on {HOST}:{PORT}")
        print("[*] Waiting for an attacker to connect...")
        
        conn, addr = s.accept()
        with conn:
            print(f"[*] Connection from {addr}")
            
            # 3. Send the public key and the target ciphertext to the attacker
            conn.sendall(public_key_pem)
            conn.sendall(b"||DELIMITER||") # Use the same delimiter as vulnerable server
            conn.sendall(TARGET_CIPHERTEXT)

            # 4. Act as an "Encryption Oracle"
            print("[*] Now acting as an encryption oracle (using secure_rsa_encrypt).")
            while True:
                try:
                    # Receive a chosen plaintext from the attacker (expecting raw plaintext)
                    chosen_plaintext = conn.recv(1024)
                    if not chosen_plaintext:
                        print("[*] Attacker disconnected.")
                        break
                    
                    print(f"[*] Received plaintext to encrypt: {chosen_plaintext.decode()}")
                    
                    # Encrypt it using the SECURE function and send it back
                    generated_ciphertext = secure_rsa_encrypt(chosen_plaintext, public_key)
                    conn.sendall(generated_ciphertext)
                    print(f"[*] Sent back corresponding ciphertext.")

                except ConnectionResetError:
                    print("[*] Attacker disconnected unexpectedly.")
                    break 
                except Exception as e:
                    print(f"[!] Server Error in oracle loop: {e}")
                    break

    print("[*] Attacker disconnected. Server shutting down.")

if __name__ == "__main__":
    main()