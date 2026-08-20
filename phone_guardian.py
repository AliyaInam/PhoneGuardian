"""Phone Guardian: safe local APK/file inspection tool.

This tool does not execute, install, modify, or attack anything. It only reads
metadata and calculates a SHA-256 hash for a file you are authorized to inspect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any


SUSPICIOUS_PERMISSIONS = {
    "android.permission.READ_SMS": (3, "Can read SMS messages"),
    "android.permission.RECEIVE_SMS": (3, "Can receive SMS messages"),
    "android.permission.SEND_SMS": (3, "Can send SMS messages"),
    "android.permission.RECORD_AUDIO": (2, "Can record audio"),
    "android.permission.CAMERA": (1, "Can use the camera"),
    "android.permission.READ_CONTACTS": (2, "Can read contacts"),
    "android.permission.READ_CALL_LOG": (3, "Can read call history"),
    "android.permission.WRITE_CALL_LOG": (3, "Can change call history"),
    "android.permission.ACCESS_FINE_LOCATION": (2, "Can access precise location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (3, "Can access location in background"),
    "android.permission.REQUEST_INSTALL_PACKAGES": (3, "Can request installation of other packages"),
    "android.permission.SYSTEM_ALERT_WINDOW": (3, "Can draw over other apps"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (3, "Accessibility service capability"),
    "android.permission.RECEIVE_BOOT_COMPLETED": (1, "Can start after device boot"),
    "android.permission.READ_EXTERNAL_STORAGE": (1, "Can read shared storage"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (3, "Broad storage access"),
}

SUSPICIOUS_STRINGS = [
    rb"powershell",
    rb"cmd\.exe",
    rb"/system/bin/sh",
    rb"Runtime\.getRuntime",
    rb"DexClassLoader",
    rb"AccessibilityService",
    rb"request_install_packages",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def scan_suspicious_strings(path: Path) -> list[str]:
    """Look for a small set of indicators without executing the file."""
    findings: list[str] = []
    try:
        data = path.read_bytes() if path.stat().st_size <= 50 * 1024 * 1024 else b""
    except OSError:
        return findings

    for pattern in SUSPICIOUS_STRINGS:
        if re.search(pattern, data, flags=re.IGNORECASE):
            findings.append(pattern.decode("utf-8", errors="replace"))
    return findings


def inspect_apk(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "is_apk": path.suffix.lower() == ".apk",
        "package_name": None,
        "app_name": None,
        "permissions": [],
        "permission_findings": [],
        "notes": [],
    }

    if path.suffix.lower() != ".apk":
        result["notes"].append("The selected file is not an APK.")
        return result

    try:
        from androguard.core.apk import APK  # type: ignore
    except ImportError:
        result["notes"].append(
            "Install APK metadata support with: python -m pip install androguard"
        )
        return result

    try:
        apk = APK(str(path))
        result["package_name"] = apk.get_package()
        result["app_name"] = apk.get_app_name()
        permissions = sorted(set(apk.get_permissions()))
        result["permissions"] = permissions
        for permission in permissions:
            if permission in SUSPICIOUS_PERMISSIONS:
                points, explanation = SUSPICIOUS_PERMISSIONS[permission]
                result["permission_findings"].append(
                    {"permission": permission, "points": points, "reason": explanation}
                )
    except Exception as exc:  # keep the scanner usable on malformed files
        result["notes"].append(f"APK metadata could not be read: {type(exc).__name__}")

    return result


def calculate_risk(apk_info: dict[str, Any], string_findings: list[str]) -> dict[str, Any]:
    score = sum(item["points"] for item in apk_info.get("permission_findings", []))
    score += len(string_findings)

    if score >= 8:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level,
        "explanation": "This is a heuristic warning, not proof that a file is malware.",
    }


def analyze(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError("Please provide a file, not a folder.")

    apk_info = inspect_apk(path)
    string_findings = scan_suspicious_strings(path)
    return {
        "tool": "Phone Guardian",
        "file_name": path.name,
        "file_size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "apk_analysis": apk_info,
        "suspicious_strings": string_findings,
        "risk": calculate_risk(apk_info, string_findings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely inspect an authorized local file or APK."
    )
    parser.add_argument("file", help="Path to the file or APK to inspect")
    parser.add_argument(
        "--output",
        default="phone_guardian_report.json",
        help="JSON report filename (default: phone_guardian_report.json)",
    )
    args = parser.parse_args()

    try:
        report = analyze(Path(args.file).expanduser())
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1

    Path(args.output).write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print("Phone Guardian report ready")
    print(f"File: {report['file_name']}")
    print(f"SHA-256: {report['sha256']}")
    print(f"Risk: {report['risk']['level']} (score {report['risk']['score']})")
    print(f"Saved to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
