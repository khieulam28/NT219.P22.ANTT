
import oqs
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

os.makedirs("keys", exist_ok=True)

# Tạo khóa RSA nếu chưa có
if not os.path.exists("keys/rsa_private.pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("keys/rsa_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))

    with open("keys/rsa_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))

# Tạo thông điệp cần ký
message = b"Xin chao the gioi"
with open("message.txt", "wb") as f:
    f.write(message)

# Ký RSA
with open("keys/rsa_private.pem", "rb") as f:
    rsa_private = serialization.load_pem_private_key(f.read(), password=None)

sig_rsa = rsa_private.sign(
    message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)
with open("sig_rsa.bin", "wb") as f:
    f.write(sig_rsa)

print("✅ Đã ký bằng RSA-PSS")

# Ký Dilithium
with oqs.Signature("Dilithium2") as signer:
    dili_public = signer.generate_keypair()
    sig_dili = signer.sign(message)
    with open("sig_dili.bin", "wb") as f:
        f.write(sig_dili)
    with open("keys/dili_public.bin", "wb") as f:
        f.write(dili_public)

print("✅ Đã ký bằng Dilithium")
