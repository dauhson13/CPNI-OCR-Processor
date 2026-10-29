import os
import secrets
import sys
import threading
import traceback
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
DEFAULT_KEY = Path.home() / ".piiscan" / "hmac.key"
KEY_BYTES = 32


def describe(exc: BaseException) -> str:
    frames = traceback.extract_tb(exc.__traceback__)
    if not frames:
        return type(exc).__name__
    f = frames[-1]
    return f"{type(exc).__name__} at {Path(f.filename).name}:{f.lineno} in {f.name}"


def is_our_bug(exc: BaseException) -> bool:
    frames = traceback.extract_tb(exc.__traceback__)
    return bool(frames) and Path(frames[-1].filename).resolve().is_relative_to(PKG_DIR)


def install_excepthook() -> None:
    def hook(exc_type, exc, tb):
        sys.stderr.write(f"piiscan: fatal {describe(exc)}\n")

    sys.excepthook = hook
    threading.excepthook = lambda a: hook(a.exc_type, a.exc_value, a.exc_traceback)


def create_key(path: Path = DEFAULT_KEY) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(secrets.token_bytes(KEY_BYTES))


def load_key(path: Path = DEFAULT_KEY) -> bytes:
    try:
        key = path.read_bytes()
    except FileNotFoundError:
        raise SystemExit(f"piiscan: no HMAC key at {path}; run `piiscan keygen` first") from None
    if len(key) != KEY_BYTES:
        raise SystemExit(f"piiscan: HMAC key at {path} is not {KEY_BYTES} bytes")
    return key
