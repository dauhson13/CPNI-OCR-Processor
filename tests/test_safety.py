import hashlib
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from conftest import KEY
from piiscan import db, safety, scan
from piiscan.synth import corpus

NET_GUARD = '''
import os, socket
_log = os.environ["PIISCAN_NET_LOG"]
def _note(what):
    with open(_log, "a") as f:
        f.write(what + "\\n")
_connect = socket.socket.connect
def connect(self, *a, **k):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        _note("connect")
        raise OSError("network blocked by test")
    return _connect(self, *a, **k)
socket.socket.connect = connect
_gai = socket.getaddrinfo
def getaddrinfo(host, *a, **k):
    if host not in (None, "localhost", "127.0.0.1", "::1"):
        _note("dns")
        raise socket.gaierror("dns blocked by test")
    return _gai(host, *a, **k)
socket.getaddrinfo = getaddrinfo
'''


def test_describe_never_includes_the_message():
    try:
        raise ValueError("SSN 123-45-6789 in cell B2")
    except ValueError as e:
        text = safety.describe(e)
    assert text.startswith("ValueError at test_safety.py:") and "123" not in text and "B2" not in text


def test_cli_canary_leak_and_no_network(tmp_path, rng):
    root = tmp_path / "share"
    truth = corpus.build(root, rng)
    canaries = {v for types in truth.values() for vals in types.values() for v in vals if len(v) >= 8}
    canaries |= {f"{v[:3]}-{v[3:5]}-{v[5:]}" for v in canaries if len(v) == 9}

    guard = tmp_path / "guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(NET_GUARD)
    net_log = tmp_path / "net.log"
    env = {**os.environ, "PYTHONPATH": str(guard), "PIISCAN_NET_LOG": str(net_log), "TMPDIR": str(tmp_path / "tmp")}
    (tmp_path / "tmp").mkdir()

    probe = subprocess.run([sys.executable, "-c", "import socket; socket.create_connection(('example.com', 80), 2)"],
                           env=env, capture_output=True)
    assert probe.returncode != 0 and net_log.read_text()
    net_log.unlink()

    key, dbfile = tmp_path / "key", tmp_path / "data" / "piiscan.db"
    subprocess.run([sys.executable, "-m", "piiscan", "keygen", "--key", str(key)], env=env, check=True, capture_output=True)
    out = subprocess.run([sys.executable, "-m", "piiscan", "scan", str(root), "--db", str(dbfile), "--key", str(key),
                          "--workers", "2"], env=env, capture_output=True, timeout=300)
    assert out.returncode == 0, out.stderr.decode()
    assert b"CUSTOMER_ACCOUNT" in out.stdout and b"PII type" in out.stdout

    again = subprocess.run([sys.executable, "-m", "piiscan", "scan", str(root), "--db", str(dbfile), "--key", str(key),
                            "--workers", "2"], env=env, capture_output=True, timeout=300)
    assert b"unchanged" in again.stdout and b"CUSTOMER_ACCOUNT" in again.stdout
    blobs_again = [again.stdout, again.stderr]

    assert not net_log.exists() or not net_log.read_text(), "something tried to reach the network"
    blobs = [out.stdout, out.stderr, *blobs_again] + [p.read_bytes() for p in dbfile.parent.iterdir()]
    for c in canaries:
        for blob in blobs:
            assert c.encode() not in blob, "a planted value leaked into output or the DB"
    leftovers = list((tmp_path / "tmp").glob("piiscan-*"))
    assert not leftovers, "temp files were left behind"
    if os.name == "posix":
        assert stat.S_IMODE(dbfile.stat().st_mode) == 0o600


def snapshot(root: Path) -> dict:
    files = {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_size, p.stat().st_mtime_ns)
             for p in sorted(root.rglob("*")) if p.is_file()}
    return files | {"__listing__": sorted(str(p.relative_to(root)) for p in root.rglob("*"))}


def test_sources_are_never_altered(tmp_path, rng):
    root = tmp_path / "share"
    corpus.build(root, rng)
    before = snapshot(root)
    paths = sorted(root.rglob("*"), reverse=True)
    for p in paths:
        p.chmod(0o555 if p.is_dir() else 0o444)
    root.chmod(0o555)
    try:
        scan.run(root, tmp_path / "piiscan.db", KEY, workers=2, timeout=60)
    finally:
        root.chmod(0o755)
        for p in paths:
            p.chmod(0o755 if p.is_dir() else 0o644)
    assert snapshot(root) == before


def test_audit_log_is_append_only(tmp_path):
    con = db.connect(tmp_path / "a.db")
    db.audit(con, "test")
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("UPDATE audit_log SET action = 'x'")
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("DELETE FROM audit_log")


def test_key_is_never_overwritten(tmp_path):
    key = tmp_path / "k" / "hmac.key"
    safety.create_key(key)
    first = key.read_bytes()
    with pytest.raises(FileExistsError):
        safety.create_key(key)
    assert key.read_bytes() == first and len(first) == safety.KEY_BYTES
    if os.name == "posix":
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
