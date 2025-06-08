from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
import os
import math
import sys

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def invert_mod(a, m):
    m0 = m
    x0, x1 = 0, 1
    if m == 1:
        return 0
    a %= m
    if a < 0:
        a += m
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if a != 1:
        raise ValueError("Modular inverse does not exist")
    if x1 < 0:
        x1 += m0
    return x1

# --- Vulnerable RSA Key Generation ---

def generate_vulnerable_rsa_key_pair(p_val, q_val, small_d_candidate):
    """Generates an RSA key pair with an intentionally small private exponent d."""
    N = p_val * q_val
    phi_N = (p_val - 1) * (q_val - 1)

    if small_d_candidate <= 0 or gcd(small_d_candidate, phi_N) != 1:
        raise ValueError("Invalid d_candidate: must be positive and coprime to phi_N")
    
    e_val = invert_mod(small_d_candidate, phi_N)
    
    # Wiener condition check for informational purposes
    try:
        n_fourth_root = math.isqrt(math.isqrt(N))
        wiener_limit_approx = (n_fourth_root / 3.0)
    except Exception:
        wiener_limit_approx = 0 

    print(f"[Key Gen] N: {N.bit_length()} bits")
    print(f"[Key Gen] Wiener Cond: d < N^(1/4)/3 => {small_d_candidate} < {wiener_limit_approx:.4f}")
    if small_d_candidate >= wiener_limit_approx:
        print("[Key Gen] WARNING: d might be too large for theoretical Wiener attack success.")

    key = RSA.construct((N, e_val, small_d_candidate, p_val, q_val))
    return key

# --- Configuration for Key Generation ---
PRIME_BITS = 512 # N will be 1024 bits

# Short message to fit RSA 1024-bit with OAEP padding (max ~62 bytes for SHA-256)
message_to_encrypt = b"Hacked! Success with Wiener Attack on a 1024-bit key!" 

PUBLIC_KEY_FILENAME = "key.pub"
CIPHERTEXT_FILENAME = "secret_message.txt" # Changed from .bin to .txt for consistency with previous output.

print("--- RSA Key & Ciphertext Generation ---")

try:
    print(f"Generating prime p ({PRIME_BITS} bits)...")
    p_for_demo = getPrime(PRIME_BITS, os.urandom)
    print(f"Generating prime q ({PRIME_BITS} bits)...")
    q_for_demo = getPrime(PRIME_BITS, os.urandom)

    while p_for_demo == q_for_demo: # Ensure p != q
        q_for_demo = getPrime(PRIME_BITS, os.urandom)
    
    N_calculated = p_for_demo * q_for_demo
    phi_N_calculated = (p_for_demo - 1) * (q_for_demo - 1)

    # d_target_value is chosen to be small enough for Wiener to work
    # 2047 is an 11-bit prime number, chosen for demo success
    d_target_value = 2047 

    # Ensure d_target_value is coprime to phi_N
    while gcd(d_target_value, phi_N_calculated) != 1:
        d_target_value += 2 
        if d_target_value > (1 << (PRIME_BITS // 4)) * 2: # Fail-safe to prevent infinite loop
            raise ValueError("Could not find a suitable d_target_value in reasonable range.")

    rsa_key = generate_vulnerable_rsa_key_pair(p_for_demo, q_for_demo, d_target_value)
    public_key = rsa_key.publickey()
    
    print(f"Key Pair Generated:")
    print(f"  N: {public_key.n}")
    print(f"  e: {public_key.e}")
    print(f"  d (secret): {rsa_key.d}")

    with open(PUBLIC_KEY_FILENAME, "wb") as f:
        f.write(public_key.export_key('PEM'))
    print(f"'{PUBLIC_KEY_FILENAME}' created.")

    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(message_to_encrypt)

    with open(CIPHERTEXT_FILENAME, "wb") as f:
        f.write(ciphertext)
    print(f"'{CIPHERTEXT_FILENAME}' created.")
    print("\nFiles ready for Wiener Attack demo.")

except ValueError as e:
    print(f"Error during key generation or encryption: {e}")
    print("Cannot create necessary files. Check parameters.")
except Exception as e:
    print(f"Unexpected error: {e}")

print("--- Generation Complete ---")