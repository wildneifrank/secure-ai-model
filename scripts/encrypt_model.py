from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import os

def encrypt_model(model_path, enc_model_path, enc_key_path, public_key_path):
    aes_key = AESGCM.generate_key(bit_length=128)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)

    with open(model_path, "rb") as f:
        model_data = f.read()

    encrypted_model = aesgcm.encrypt(nonce, model_data, None)
    with open(enc_model_path, "wb") as f:
        f.write(nonce + encrypted_model)

    # RSA
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(enc_key_path, "wb") as f:
        f.write(encrypted_key)

    print("Model and AES key encrypted.")

if __name__ == "__main__":
    encrypt_model(
    "yolov8n.pt", 
    "model/model.pth.enc",
    "key/aes_key.enc",
    "key/public.pem"
)

