import io
import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import torch
from ultralytics.nn.tasks import DetectionModel
import torch.serialization

torch.serialization.add_safe_globals([DetectionModel])

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def decrypt_aes_key(enc_key_path, private_key_path):
    with open(enc_key_path, "rb") as f:
        enc_key = f.read()
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_model(model_path, aes_key):
    with open(model_path, "rb") as f:
        data = f.read()
    nonce, ciphertext = data[:12], data[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def load_model_from_bytes(model_bytes: bytes):
    buffer = io.BytesIO(model_bytes)
    loaded = torch.load(buffer, map_location=torch.device("cpu"))

    if isinstance(loaded, dict):
        if "model" in loaded:
            model_data = loaded["model"]
            if isinstance(model_data, DetectionModel):
                model = model_data
            elif isinstance(model_data, dict):
                model = DetectionModel('yolov8n.yaml')
                model.load_state_dict(model_data)
            else:
                raise TypeError(f"Unsupported model data type: {type(model_data)}")
        else:
            model = DetectionModel('yolov8n.yaml')
            model.load_state_dict(loaded)
    elif isinstance(loaded, DetectionModel):
        model = loaded
    else:
        raise TypeError(f"Unexpected loaded type: {type(loaded)}")

    model.eval()
    return model

