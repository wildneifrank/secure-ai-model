import sys
import os
import hashlib
import ctypes
import inspect
import time
import threading
import sysconfig
import psutil
import traceback

# ========== Proteções Anti-Debug ==========

def detect_and_block_debugger():
    if sys.gettrace() is not None:
        print("Debugger detectado via sys.gettrace(). Abortando.")
        sys.exit(1)
        
    for frame_info in inspect.stack():
        filename = frame_info.filename.lower()
        if any(debugger_str in filename for debugger_str in ["pdb", "pydevd", "debug"]):
            print("[!] Debugger detectado via stack trace!")
            sys.exit(1)

    if "debugpy" in sys.modules:
        print("Debugger detectado via módulo debugpy carregado. Abortando.")
        sys.exit(1)

    for thread in threading.enumerate():
        if thread.name.startswith("pydevd"):
            print("Debugger detectado via thread pydevd. Abortando.")
            sys.exit(1)

    if os.name == "nt":
        try:
            if ctypes.windll.kernel32.IsDebuggerPresent() != 0:
                print("Debugger detectado via IsDebuggerPresent. Abortando.")
                sys.exit(1)
        except Exception:
            pass

    for var in ["PYTHONBREAKPOINT", "PYDEV_DEBUG"]:
        if os.getenv(var):
            print(f"Debugger detectado via variável {var}. Abortando.")
            sys.exit(1)

    t1 = time.perf_counter()
    for _ in range(10000):
        pass
    t2 = time.perf_counter()
    if (t2 - t1) > 0.01:
        print("Debugger detectado via atraso suspeito. Abortando.")
        sys.exit(1)

# ========== Proteções contra Hooking e Injeção ==========

def detect_malicious_modules():
    suspicious_modules = [
        "frida", "pydbg", "ctypeshook", "pyhook", "pydevd", "winappdbg",
        "pyinjector", "injector", "pymem", "ptrace", "volatility", "hexdump",
        "pyxhook", "capstone", "keystone", "unicorn", "tracer", "hooker",
        "ipdb", "rpdb", "remote_pdb", "pydebugger", "pytrace", "pyspoofer",
        "python_hooker", "hunter", "snoop", "manhole", "xhook", "pyrebox",
        "objdump"
    ]

    suspicious_processes = [
        "frida-server", "frida-trace", "ollydbg", "ida64", "ida32", "x64dbg", "x32dbg",
        "wireshark", "dnspy", "cheatengine", "gdb", "radare2", "immunitydebugger"
    ]

    # 1. Verifica se módulos suspeitos estão carregados
    for mod in sys.modules:
        mod_lower = mod.lower()
        if any(s in mod_lower for s in suspicious_modules):
            print(f"[!] Módulo suspeito detectado: {mod}. Abortando.")
            sys.exit(1)

    # 2. Verifica caminhos suspeitos para módulos que não são do stdlib/site-packages
    allowed_paths = [
        sysconfig.get_paths()["stdlib"].lower(),
        os.path.join(sys.base_prefix.lower(), "dlls"),
        os.path.join(sys.base_prefix.lower(), "libs"),
        os.path.join(sys.base_prefix.lower(), "lib", "site-packages"),
    ]

    for mod_name, mod in sys.modules.items():
        path = getattr(mod, "__file__", None)
        if path is None:
            # built-in ou módulos especiais, ignorar
            continue
        path = os.path.abspath(path).lower()

        if mod_name == "__main__" or "pyarmor_runtime" in mod_name:
            continue
        if "dist_protected" in path:
            continue
        if any(path.startswith(p) for p in allowed_paths):
            continue

        print(f"[!] Módulo {mod_name} carregado de caminho suspeito: {path}")
        sys.exit(1)

    # 3. Verifica se há processos maliciosos ativos
    for proc in psutil.process_iter(["name", "exe", "cmdline"]):
        try:
            name = (proc.info["name"] or "").lower()
            cmd = " ".join(proc.info["cmdline"] or []).lower()
            if any(s in name or s in cmd for s in suspicious_processes):
                print(f"[!] Processo suspeito detectado: {name or cmd}. Abortando.")
                sys.exit(1)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# ========== Verificação de Integridade ==========

def check_integrity(file_path: str, expected_hash: str):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        if file_hash != expected_hash:
            print("Integridade comprometida. Abortando.")
            sys.exit(1)
    except Exception as e:
        print(f"Falha ao verificar integridade: {e}")
        sys.exit(1)

def check_function_integrity(fn, expected_source_snippet: str):
    source = inspect.getsource(fn)
    if expected_source_snippet not in source:
        print("Função alterada! Abortando.")
        sys.exit(1)

