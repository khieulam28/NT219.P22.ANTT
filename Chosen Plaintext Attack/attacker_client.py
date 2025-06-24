# attacker_client.py (FIXED for complete ciphertext reception)
import socket
from Crypto.PublicKey import RSA

# --- Configuration ---
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 8080        # The port used by the server

# --- The attacker must know the set of possible plaintexts ---
POSSIBLE_COMMANDS = [
    b"ATTACK_NORTH",
    b"HOLD_POSITION",
    b"RETREAT_SOUTH",
    b"DEPLOY_ASSETS"
]

def main():
    """Main attacker function."""
    print("--- CPA Attacker Client ---")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            print(f"[*] Connected to server at {HOST}:{PORT}")

            # 1. Receive the public key and target ciphertext from the server
            data_received = b""
            while b"||DELIMITER||" not in data_received:
                packet = s.recv(4096)
                if not packet:
                    raise ConnectionError("Server disconnected while receiving initial data.")
                data_received += packet
            
            parts = data_received.split(b"||DELIMITER||", 1)
            public_key_pem = parts[0]
            TARGET_CIPHERTEXT_partial = parts[1] # This might not be the full ciphertext yet

            public_key_obj = RSA.import_key(public_key_pem) # Import key to get size
            key_size_bytes = (public_key_obj.n.bit_length() + 7) // 8 # Calculate expected ciphertext size

            TARGET_CIPHERTEXT = TARGET_CIPHERTEXT_partial
            # Loop to ensure full TARGET_CIPHERTEXT is received
            while len(TARGET_CIPHERTEXT) < key_size_bytes:
                 packet = s.recv(4096)
                 if not packet:
                     raise ConnectionError("Server disconnected while receiving full target ciphertext.")
                 TARGET_CIPHERTEXT += packet
            
            TARGET_CIPHERTEXT = TARGET_CIPHERTEXT[:key_size_bytes] # Trim any extra data

            print(f"[*] Received Public Key from server.")
            print(f"[*] Received Target Ciphertext (Hex): {TARGET_CIPHERTEXT.hex()}")
            print("-" * 30)
            
            # 2. --- The Chosen Plaintext Attack begins ---
            print("[*] Starting Chosen Plaintext Attack...")
            
            found_secret = None
            
            for command in POSSIBLE_COMMANDS:
                chosen_plaintext = command
                print(f"[*] Choosing plaintext: '{chosen_plaintext.decode()}' and sending to oracle...")

                # 3. Send the chosen plaintext (RAW) to the server's encryption oracle
                s.sendall(chosen_plaintext)
                
                # 4. Receive the resulting ciphertext from the oracle
                generated_ciphertext = b""
                # THIS IS THE CRUCIAL FIX: Loop to ensure full ciphertext is received
                while len(generated_ciphertext) < key_size_bytes:
                    packet = s.recv(4096) # Receive in chunks
                    if not packet:
                        print("[!] Server disconnected while receiving oracle's ciphertext.")
                        found_secret = "CONNECTION_LOST" # Flag for connection loss
                        break
                    generated_ciphertext += packet
                
                if found_secret == "CONNECTION_LOST":
                    break # Exit outer loop if connection was lost

                # Ensure it's exactly the expected size (in case extra data was received)
                generated_ciphertext = generated_ciphertext[:key_size_bytes]

                print(f"    -> Oracle returned ciphertext (Hex): {generated_ciphertext.hex()}")

                # 5. Compare the oracle's output with the target ciphertext
                if generated_ciphertext == TARGET_CIPHERTEXT:
                    print(f"\n[+] SUCCESS! Match found!")
                    print(f"[+] The secret command is: {chosen_plaintext.decode()}")
                    found_secret = chosen_plaintext
                    break
                else:
                    print("    -> No match. Trying next command.\n")

            if not found_secret:
                print("\n[-] ATTACK FAILED. No matching command found in the list.")
                # This message provides context for both vulnerable and secure servers
                print("    This is expected if the server uses probabilistic padding (like PKCS1_OAEP).")

        except ConnectionRefusedError:
            print(f"[!] Connection failed. Is the server running on {HOST}:{PORT}?")
        except ConnectionError as ce:
            print(f"[!] Connection error: {ce}")
        except Exception as e:
            print(f"[!] An unexpected error occurred: {e}")

    print("[*] Attacker client finished.")

if __name__ == "__main__":
    main()