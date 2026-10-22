import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

from . import db

LABEL = "com.piiscan.scan"
TASK = "piiscan-scan"
LOG = db.PROJECT_DIR / "data" / "logs" / "scan.log"
PLIST = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _command() -> list[str]:
    uv = shutil.which("uv")
    if not uv:
        raise SystemExit("piiscan: uv wasn't found on PATH")
    return [uv, "run", "--project", str(db.PROJECT_DIR), str(db.PROJECT_DIR / "main.py"), "scan"]


def launchd_plist(hour: int, minute: int) -> bytes:
    return plistlib.dumps({
        "Label": LABEL, "ProgramArguments": _command(), "WorkingDirectory": str(db.PROJECT_DIR),
        "StartCalendarInterval": {"Hour": hour, "Minute": minute},
        "StandardOutPath": str(LOG), "StandardErrorPath": str(LOG),
    })


WRAPPER = db.PROJECT_DIR / "data" / "scheduled_scan.cmd"


def windows_wrapper() -> str:
    return f"@echo off\r\n{subprocess.list2cmdline(_command())} >> \"{LOG}\" 2>&1\r\n"


def schtasks_args(hour: int, minute: int) -> list[str]:
    return ["schtasks", "/Create", "/F", "/SC", "DAILY", "/TN", TASK, "/ST", f"{hour:02d}:{minute:02d}",
            "/TR", f'"{WRAPPER}"']


def install(at: str) -> str:
    hour, minute = (int(x) for x in at.split(":"))
    if not (0 <= hour < 24 and 0 <= minute < 60):
        raise SystemExit("piiscan: give the time as HH:MM, 24-hour")
    LOG.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        WRAPPER.write_text(windows_wrapper(), encoding="utf-8", newline="")
        subprocess.run(schtasks_args(hour, minute), check=True, capture_output=True)
        return f"Task Scheduler task '{TASK}' runs daily at {at}; output goes to {LOG}"
    PLIST.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(PLIST)], capture_output=True)
    PLIST.write_bytes(launchd_plist(hour, minute))
    subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(PLIST)], check=True, capture_output=True)
    return f"launchd job '{LABEL}' runs daily at {at}; output goes to {LOG}"


def remove() -> str:
    if sys.platform == "win32":
        subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK], capture_output=True)
        WRAPPER.unlink(missing_ok=True)
        return f"removed Task Scheduler task '{TASK}'"
    subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(PLIST)], capture_output=True)
    PLIST.unlink(missing_ok=True)
    return f"removed launchd job '{LABEL}'"
