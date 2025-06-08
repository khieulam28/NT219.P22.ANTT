import math
import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP # Added for proper decryption

# --- Helper Functions ---

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

# --- Continued Fraction and Convergents ---

def get_continued_fraction_coeffs(numerator, denominator):
    coeffs = []
    while denominator:
        coeffs.append(numerator // denominator)
        numerator, denominator = denominator, numerator % denominator
    return coeffs

def get_convergents(continued_fraction_coeffs):
    h_prev2, h_prev1 = 0, 1 # Numerator parts
    k_prev2, k_prev1 = 1, 0 # Denominator parts

    for q_i in continued_fraction_coeffs:
        h_curr = q_i * h_prev1 + h_prev2
        k_curr = q_i * k_prev1 + k_prev2
        yield h_curr, k_curr 
        h_prev2, h_prev1 = h_prev1, h_curr
        k_prev2, k_prev1 = k_prev1, k_curr

# --- Wiener Attack Algorithm ---

def wiener_attack(e, n):
    print(f"\n--- Wiener Attack Started ---")
    print(f"Public N: {n}")
    print(f"Public e: {e}")

    coeffs = get_continued_fraction_coeffs(e, n)
    print(f"Partial quotients: {coeffs}")

    print(f"Checking convergents for d...")
    for k_candidate, d_candidate in get_convergents(coeffs):
        if d_candidate <= 0 or k_candidate == 0:
            continue

        if (e * d_candidate - 1) % k_candidate == 0:
            phi_N_candidate = (e * d_candidate - 1) // k_candidate
            
            if not (0 < phi_N_candidate < n and phi_N_candidate % 2 == 0):
                continue

            S_candidate = n - phi_N_candidate + 1 
            discriminant = S_candidate**2 - 4 * n
            
            if discriminant < 0:
                continue 
            
            if sys.version_info >= (3, 8):
                sqrt_discriminant = math.isqrt(discriminant)
            else:
                sqrt_discriminant = int(math.sqrt(discriminant))

            if sqrt_discriminant * sqrt_discriminant == discriminant:
                p_candidate = (S_candidate + sqrt_discriminant) // 2
                q_candidate = (S_candidate - sqrt_discriminant) // 2
                
                if p_candidate > 0 and q_candidate > 0 and p_candidate * q_candidate == n:
                    print(f"\n--- d Found! ---")
                    print(f"d: {d_candidate}")
                    print(f"k: {k_candidate}")
                    print(f"phi(N): {phi_N_candidate}")
                    print(f"Factored N: p={p_candidate}, q={q_candidate}")
                    print(f"------------------\n")
                    return d_candidate
    
    print(f"\n--- Wiener Attack Failed ---")
    return None

# --- File Reading Functions ---

def get_pubkey(f_path):
    with open(f_path) as pub:
        key = RSA.importKey(pub.read())
    return (key.n, key.e)

def get_ciphertext(f_path):
    with open(f_path, 'rb') as ct:
        return bytes_to_long(ct.read())

# --- Main Demo Execution ---

if __name__ == '__main__':
    print("===== WIENER ATTACK DEMO =====")

    PUBLIC_KEY_FILENAME = './key.pub'
    CIPHERTEXT_FILENAME = './secret_message.txt' # Changed from .bin to .txt for consistency with generate.py

    try:
        current_n, current_e = get_pubkey(PUBLIC_KEY_FILENAME)
        print(f"Loaded N from '{PUBLIC_KEY_FILENAME}'.")
        print(f"Loaded E from '{PUBLIC_KEY_FILENAME}'.")
    except FileNotFoundError:
        print(f"Error: '{PUBLIC_KEY_FILENAME}' not found. Run generate_keys_and_flag.py first.")
        sys.exit(1)

    try:
        current_c = get_ciphertext(CIPHERTEXT_FILENAME)
        print(f"Loaded Ciphertext from '{CIPHERTEXT_FILENAME}'.")
    except FileNotFoundError:
        print(f"Error: '{CIPHERTEXT_FILENAME}' not found. Run generate_keys_and_flag.py first.")
        sys.exit(1)

    d_recovered = wiener_attack(current_e, current_n)
    print(f"Recovered d: {d_recovered}")

    if d_recovered is None:
        print("Attack failed.")
    else:
        print("\nAttack successful! Decrypting message.")
        try:
            # Reconstruct RSA key with recovered 'd' for proper OAEP decryption
            rsa_key_for_decryption = RSA.construct((current_n, current_e, d_recovered))
            
            # Create OAEP cipher object for decryption
            cipher_rsa_dec = PKCS1_OAEP.new(rsa_key_for_decryption)
            
            # Decrypt and remove padding
            plaintext_bytes = cipher_rsa_dec.decrypt(long_to_bytes(current_c))
            
            print(f"Decrypted Message: {plaintext_bytes.decode('utf-8')}")
        except Exception as decrypt_err:
            print(f"Error during decryption: {decrypt_err}")

    print("\n===== DEMO COMPLETE =====")