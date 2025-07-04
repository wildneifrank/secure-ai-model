import hashlib
from pathlib import Path

def generate_hash_registry_obfuscated(base_dir, output_path):
    from pathlib import Path
    import hashlib

    base_path = Path(base_dir)
    file_hashes = {}

    model_path = Path("model/model.pth.enc")

    targets = [
        base_path / "main.py",
        model_path
    ] + list((base_path / "scripts").rglob("*.py"))

    for path in targets:
        if not path.is_file():
            continue
        rel_path = path.as_posix()
        var_name = rel_path.replace("/", "_").replace(".", "_").upper()
        with open(path, "rb") as f:
            file_hashes[var_name] = hashlib.sha256(f.read()).hexdigest()

    with open(output_path, "w") as f:
        f.write("# Hashes dos arquivos ofuscados (modo produção)\n\n")
        for var_name, file_hash in file_hashes.items():
            f.write(f"{var_name} = \"{file_hash}\"\n")

if __name__ == "__main__":
    generate_hash_registry_obfuscated("dist_protected", "dist_protected/hash_registry_obfuscated.py")
    print("Arquivo hash_registry_obfuscated.py criado com os hashes ofuscados para produção.")
