# attacker_client.py
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
                    break
                data_received += packet
            
            parts = data_received.split(b"||DELIMITER||", 1)
            public_key_pem = parts[0]
            TARGET_CIPHERTEXT = parts[1]

            # The attacker needs to keep receiving until the full ciphertext is there
            # (RSA ciphertext length depends on key size)
            key_size_bytes = (RSA.import_key(public_key_pem).n.bit_length() + 7) // 8
            while len(TARGET_CIPHERTEXT) < key_size_bytes:
                 packet = s.recv(4096)
                 if not packet:
                     break
                 TARGET_CIPHERTEXT += packet

            print(f"[*] Received Public Key from server.")
            print(f"[*] Received Target Ciphertext (Hex): {TARGET_CIPHERTEXT.hex()}")
            print("-" * 30)
            
            # 2. --- The Chosen Plaintext Attack begins ---
            print("[*] Starting Chosen Plaintext Attack...")
            
            found_secret = None
            
            for command in POSSIBLE_COMMANDS:
                # This is the "CHOICE" step. We are choosing a plaintext to encrypt.
                chosen_plaintext = command
                print(f"[*] Choosing plaintext: '{chosen_plaintext.decode()}' and sending to oracle...")

                # 3. Send the chosen plaintext to the server's encryption oracle
                s.sendall(chosen_plaintext)
                
                # 4. Receive the resulting ciphertext from the oracle
                generated_ciphertext = s.recv(4096)
                
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

        except ConnectionRefusedError:
            print(f"[!] Connection failed. Is the server running on {HOST}:{PORT}?")
        except Exception as e:
            print(f"[!] An error occurred: {e}")

    print("[*] Attacker client finished.")

if __name__ == "__main__":
    main()