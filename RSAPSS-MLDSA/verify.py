# verify.py
import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load message
with open("message.txt", "rb") as f:
    message = f.read()

# === XÁC MINH RSA ===
with open("sig_rsa.bin", "rb") as f:
    sig_rsa = f.read()

with open("keys/rsa_public.pem", "rb") as f:
    rsa_public = serialization.load_pem_public_key(f.read())

try:
    rsa_public.verify(
        sig_rsa,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("✅ Chữ ký RSA hợp lệ.")
except Exception as e:
    print("❌ Chữ ký RSA không hợp lệ:", str(e))

# === XÁC MINH DILITHIUM ===
with open("sig_dili.bin", "rb") as f:
    sig_dili = f.read()

with open("keys/dili_public.bin", "rb") as f:
    dili_public = f.read()

with oqs.Signature("Dilithium2", dili_public) as verifier:
    if verifier.verify(message, sig_dili, dili_public):
        print("✅ Chữ ký Dilithium hợp lệ.")
    else:
        print("❌ Chữ ký Dilithium không hợp lệ.")
