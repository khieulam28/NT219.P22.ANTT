# generate_keys.py
import oqs
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

os.makedirs("keys", exist_ok=True)

# === TẠO KHÓA RSA ===
if not os.path.exists("keys/rsa_private.pem"):
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public = rsa_private.public_key()

    # Lưu khóa riêng
    with open("keys/rsa_private.pem", "wb") as f:
        f.write(rsa_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))

    # Lưu khóa công khai
    with open("keys/rsa_public.pem", "wb") as f:
        f.write(rsa_public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("✅ Đã tạo và lưu khóa RSA")

else:
    print("🔁 Đã tồn tại khóa RSA, không cần tạo lại.")

# === TẠO KHÓA DILITHIUM ===
if not os.path.exists("keys/dili_public.bin"):
    with oqs.Signature("Dilithium2") as signer:
        dili_public = signer.generate_keypair()  # public key
        dili_private = signer.export_secret_key()  # private key (nếu bạn muốn lưu)

        with open("keys/dili_public.bin", "wb") as f:
            f.write(dili_public)

        with open("keys/dili_private.bin", "wb") as f:
            f.write(dili_private)

    print("✅ Đã tạo và lưu khóa Dilithium")

else:
    print("🔁 Đã tồn tại khóa Dilithium, không cần tạo lại.")
