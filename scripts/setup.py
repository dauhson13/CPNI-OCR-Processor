import importlib
import os
import platform
import sys

os.environ["HF_HUB_OFFLINE"] = "0"

REQUIRED = ["pypdfium2", "pypdf", "defusedxml", "olefile", "xlrd", "striprtf", "extract_msg", "pypff", "PIL",
            "pillow_heif", "pebble", "msoffcrypto", "cryptography", "torch", "doctr", "cv2", "transformers", "faker"]
if sys.platform == "win32":
    REQUIRED.append("win32security")


def main() -> int:
    ok = True
    print(f"Python {platform.python_version()} on {platform.system()} {platform.machine()}")
    if sys.version_info[:2] != (3, 12):
        print("  FAIL    expected Python 3.12; run this with `uv run`")
        ok = False
    for mod in REQUIRED:
        try:
            importlib.import_module(mod)
            print(f"  ok      {mod}")
        except Exception as e:
            print(f"  FAIL    {mod}: {type(e).__name__}")
            ok = False

    from piiscan import safety
    from piiscan.extract import legacy

    if safety.DEFAULT_KEY.exists():
        print(f"  ok      HMAC key at {safety.DEFAULT_KEY}")
    else:
        safety.create_key()
        print(f"  created HMAC key at {safety.DEFAULT_KEY}  <- back this up; a new key breaks dedupe across runs")
    from piiscan import ocr

    if not ocr.models_ready():
        print("  ...     downloading OCR models into models/ (the only time piiscan uses the network)")
        from piiscan.ocr import orientation

        orientation.predictor()
    if ocr.models_ready():
        print(f"  ok      OCR models in {ocr.MODELS_DIR}  (device: {ocr.device()})")
    else:
        print("  FAIL    OCR models could not be downloaded")
        ok = False
    from piiscan.ocr import handwriting
    from piiscan.synth import handwriting as hw

    base = ocr.MODELS_DIR / "hf" / "trocr-small-stage1"
    if not (base / "config.json").exists():
        print("  ...     downloading the handwriting base model (TrOCR-small, printed-text pre-training only)")
        from huggingface_hub import snapshot_download

        snapshot_download("microsoft/trocr-small-stage1", local_dir=base)
    if not hw.fonts():
        print("  ...     downloading handwriting fonts (OFL/Apache) for synthetic training data")
        hw.download_fonts()
    print(f"  ok      handwriting base model and {len(hw.fonts())} fonts")
    if handwriting.available():
        print("  ok      trained handwriting model")
    else:
        print("  note    no trained handwriting model yet: run `uv run main.py train` (about 30 min on a Mac GPU)")
    if legacy.soffice():
        print("  ok      LibreOffice (legacy .doc/.ppt)")
    else:
        print("  note    LibreOffice not found: .doc/.ppt files will be recorded as 'unsupported'.")
        print("          Windows: winget install TheDocumentFoundation.LibreOffice")
        print("          macOS:   brew install --cask libreoffice")
    print("ready" if ok else "setup incomplete")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
