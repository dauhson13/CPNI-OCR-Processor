import io
import random

import pytest

from piiscan import worker
from piiscan.detect import value_hmac
from piiscan.synth.values import digits

KEY = b"k" * 32


@pytest.fixture
def rng():
    return random.Random(1234)


@pytest.fixture
def scan_bytes():
    worker.init(KEY, quiet=False)

    def run(data: bytes, name: str) -> list[dict]:
        out: list[dict] = []
        worker.scan_blob(io.BytesIO(data), name, None, 0, out)
        return out

    return run


def found(records: list[dict]) -> set[tuple[str, str]]:
    return {(f["pii_type"], f["value_hmac"]) for r in records for f in r["findings"]}


def expect(pii_type: str, value: str) -> tuple[str, str]:
    normalized = value.replace("-", "").upper() if pii_type == "DRIVERS_LICENSE" else digits(value)
    return pii_type, value_hmac(KEY, pii_type, normalized)
