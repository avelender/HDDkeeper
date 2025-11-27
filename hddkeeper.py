import subprocess
import sys
import json
import csv
import argparse
import os
import re
import base64
import getpass
import platform
import smtplib
import ssl
import shutil
from email.message import EmailMessage
from ctypes import wintypes, windll, byref, Structure, POINTER, cast, create_string_buffer, c_byte
from datetime import datetime
from shutil import which
import threading


def _run(cmd, shell=False):
    try:
        si = None
        cf = 0
        if os.name == "nt":
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                cf = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            except Exception:
                si = None
                cf = 0
        p = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", startupinfo=si, creationflags=cf)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)


def _powershell_available():
    return which("powershell") is not None or which("powershell.exe") is not None


def _wmic_available():
    return which("wmic") is not None or os.path.exists(os.path.join(os.environ.get("SystemRoot", r"C:\\Windows"), "System32", "wbem", "wmic.exe"))


def _run_ps(script):
    exe = "powershell"
    if which("powershell.exe"):
        exe = "powershell.exe"
    return _run([exe, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", script])


def _try_ps_json(script):
    if not _powershell_available():
        return None
    rc, out, err = _run_ps(script + " | ConvertTo-Json -Depth 4")
    if rc != 0 or not out.strip():
        return None
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        return None
    except Exception:
        return None


def _collect_ps_win32_diskdrive():
    script = "Get-WmiObject -Class Win32_DiskDrive | Select-Object Model,SerialNumber,InterfaceType,Size,PNPDeviceID"
    data = _try_ps_json(script)
    return data or []


def _collect_ps_physicaldisk():
    script = "Get-PhysicalDisk | Select-Object FriendlyName,SerialNumber,UniqueId,BusType,Size"
    data = _try_ps_json(script)
    return data or []


def _collect_wmic_diskdrive():
    exe = "wmic"
    if not which("wmic"):
        alt = os.path.join(os.environ.get("SystemRoot", r"C:\\Windows"), "System32", "wbem", "wmic.exe")
        exe = alt if os.path.exists(alt) else "wmic"
    cmd = [exe, "diskdrive", "get", "Model,SerialNumber,InterfaceType,Size,PNPDeviceID", "/format:csv"]
    rc, out, err = _run(cmd)
    if rc != 0 or not out:
        return []
    lines = [l for l in out.splitlines() if l.strip()]
    if not lines or "," not in lines[0]:
        return []
    reader = csv.DictReader(lines)
    rows = []
    for r in reader:
        rows.append({
            "Model": r.get("Model"),
            "SerialNumber": r.get("SerialNumber"),
            "InterfaceType": r.get("InterfaceType"),
            "Size": r.get("Size"),
            "PNPDeviceID": r.get("PNPDeviceID"),
        })
    return rows


def _normalize_bus(interface_type, pnp, bus_type=None):
    if bus_type:
        b = str(bus_type).strip().upper()
        if b.isdigit():
            m = {
                "1": "SCSI",  # Unknown mapping safety; Windows enum differs across docs
                "2": "ATAPI",
                "3": "ATA",
                "4": "SCSI",
                "5": "SATA",
                "6": "SAS",
                "7": "SAS",
                "8": "NVME",
                "9": "SD",
                "10": "MMC",
                "11": "VIRTUAL",
                "12": "FILEBACKED",
                "13": "SPACES",
                "14": "NVME",
            }
            return m.get(b, "Unknown")
        if b in {"SAS", "SATA", "NVME", "SCSI", "USB"}:
            return b
    it = (interface_type or "").strip().upper()
    if "NVME" in (pnp or "").upper():
        return "NVME"
    if it == "USB":
        return "USB"
    if it == "SAS":
        return "SAS"
    if it in {"IDE", "ATA", "ATAPI"}:
        return "SATA"
    if it == "SCSI":
        return "SCSI"
    if it == "RAID":
        return "RAID"
    return "Unknown"


def _is_usb(interface_type, pnp):
    it = (interface_type or "").strip().upper()
    if it == "USB":
        return True
    if (pnp or "").upper().find("USBSTOR") >= 0:
        return True
    return False


def _clean_serial(s):
    if not s:
        return None
    s = str(s).strip()
    s = re.sub(r"\s+", "", s)
    return s or None


def _mk_id(serial, unique, pnp, model, size):
    if serial:
        return serial.upper()
    if unique:
        return str(unique).strip().upper()
    if pnp:
        return str(pnp).strip().upper()
    return f"{(model or '').strip()}|{size}"


def scan_disks():
    results = []
    keys = set()

    # Primary: PowerShell Win32_DiskDrive (when available)
    for r in _collect_ps_win32_diskdrive():
        model = r.get("Model")
        serial = _clean_serial(r.get("SerialNumber"))
        itype = r.get("InterfaceType")
        size = int(r.get("Size") or 0)
        pnp = r.get("PNPDeviceID")
        if _is_usb(itype, pnp):
            continue
        bus = _normalize_bus(itype, pnp)
        rid = _mk_id(serial, None, pnp, model, size)
        if rid in keys:
            continue
        keys.add(rid)
        results.append({
            "id": rid,
            "serial": serial,
            "model": model,
            "size_bytes": size,
            "bus": bus,
            "source": "ps_wmi",
        })

    # Fallback: WMIC (Win7 friendly)
    if not results or _wmic_available():
        for r in _collect_wmic_diskdrive():
            model = r.get("Model")
            serial = _clean_serial(r.get("SerialNumber"))
            itype = r.get("InterfaceType")
            size = int(r.get("Size") or 0)
            pnp = r.get("PNPDeviceID")
            if _is_usb(itype, pnp):
                continue
            bus = _normalize_bus(itype, pnp)
            rid = _mk_id(serial, None, pnp, model, size)
            if rid in keys:
                continue
            keys.add(rid)
            results.append({
                "id": rid,
                "serial": serial,
                "model": model,
                "size_bytes": size,
                "bus": bus,
                "source": "wmic",
            })

    # Optional: PhysicalDisk (Win8+), enrich or add
    phys = _collect_ps_physicaldisk()
    for r in phys:
        serial = _clean_serial(r.get("SerialNumber"))
        unique = r.get("UniqueId")
        model = r.get("FriendlyName")
        size = int(r.get("Size") or 0)
        bus = _normalize_bus(None, None, r.get("BusType"))
        rid = _mk_id(serial, unique, None, model, size)
        if rid in keys:
            continue
        keys.add(rid)
        results.append({
            "id": rid,
            "serial": serial,
            "model": model,
            "size_bytes": size,
            "bus": bus,
            "source": "physicaldisk",
        })

    # Optional: storcli (LSI/Broadcom) if available
    sp = _find_storcli()
    if sp:
        for r in _collect_storcli(sp):
            serial = _clean_serial(r.get("serial"))
            model = r.get("model")
            size = int(r.get("size_bytes") or 0)
            bus = r.get("bus") or "SAS"
            rid = _mk_id(serial, None, None, model, size)
            if rid in keys:
                continue
            keys.add(rid)
            results.append({
                "id": rid,
                "serial": serial,
                "model": model,
                "size_bytes": size,
                "bus": bus,
                "source": "storcli",
            })

    return results


def _find_storcli():
    names = ["storcli64.exe", "storcli.exe", "storcli64", "storcli"]
    for n in names:
        p = which(n)
        if p:
            return p
    cand = []
    pd = os.environ.get("ProgramData", r"C:\\ProgramData")
    pf = os.environ.get("ProgramFiles", r"C:\\Program Files")
    pfx = os.environ.get("ProgramFiles(x86)", r"C:\\Program Files (x86)")
    cand.append(os.path.join(pd, "HDDkeeper", "bin", "storcli64.exe"))
    prefixes = [
        os.path.join(pf, "Broadcom"),
        os.path.join(pfx, "Broadcom"),
        os.path.join(pf, "Avago"),
        os.path.join(pfx, "Avago"),
        os.path.join(pf, "LSI"),
        os.path.join(pfx, "LSI"),
        os.path.join(pf, "MegaRAID"),
        os.path.join(pfx, "MegaRAID"),
    ]
    for base in prefixes:
        cand.append(os.path.join(base, "storcli", "storcli64.exe"))
        cand.append(os.path.join(base, "StorCLI", "storcli64.exe"))
        cand.append(os.path.join(base, "storcli64.exe"))
    for c in cand:
        if os.path.exists(c):
            return c
    return None


def _run_storcli(path, args):
    return _run([path] + args)


def _parse_size_to_bytes(s):
    if not s:
        return 0
    m = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*(TB|GB|MB|KB|B)", str(s), re.IGNORECASE)
    if not m:
        return 0
    val = float(m.group(1))
    unit = m.group(2).upper()
    mul = {"TB": 10**12, "GB": 10**9, "MB": 10**6, "KB": 10**3, "B": 1}.get(unit, 1)
    return int(val * mul)


def _format_bytes(n):
    try:
        v = int(n or 0)
    except Exception:
        return ""
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(v)
    while f >= 1024.0 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    if i == 0:
        return f"{int(f)} {units[i]}"
    return f"{f:.1f} {units[i]}"

def _extract_drives_from_obj(obj):
    out = []
    seen = set()

    def add_one(d):
        serial = d.get("SN") or d.get("S/N") or d.get("Serial") or d.get("Serial No") or d.get("SerialNumber")
        model = d.get("Model") or d.get("Model Number") or d.get("ModelNumber") or d.get("ModelNum") or d.get("Vendor")
        size = d.get("Size") or d.get("Capacity")
        intf = d.get("Intf") or d.get("Interface") or d.get("Protocol")
        serial = _clean_serial(serial)
        if not serial:
            return
        key = (serial, str(model))
        if key in seen:
            return
        seen.add(key)
        out.append({
            "serial": serial,
            "model": model,
            "size_bytes": _parse_size_to_bytes(size),
            "bus": _normalize_bus(intf, None, intf),
        })

    def walk(x):
        if isinstance(x, dict):
            # Candidate lists of drives
            for v in x.values():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    # Check if dicts look like drives
                    has_serial_key = any(any(k2.lower() in {"sn", "s/n", "serial", "serialnumber", "serial no"} for k2 in d.keys()) for d in v)
                    if has_serial_key:
                        for d in v:
                            if isinstance(d, dict):
                                add_one(d)
                walk(v)
        elif isinstance(x, list):
            for it in x:
                walk(it)

    walk(obj)
    return out


def _parse_storcli_json(text):
    if not text:
        return None
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        js = text[start:end+1]
        return json.loads(js)
    except Exception:
        return None


def _collect_storcli(path):
    tries = [
        ["show", "J"],
        ["/call", "/eall", "/sall", "show", "J"],
        ["/call", "/eall", "/sall", "show", "all", "J"],
    ]
    data = None
    for args in tries:
        rc, out, err = _run_storcli(path, args)
        if rc == 0:
            data = _parse_storcli_json(out)
            if data:
                break
    if not data:
        return []
    return _extract_drives_from_obj(data)

def data_dir():
    base = os.environ.get("ProgramData", r"C:\\ProgramData")
    return os.path.join(base, "HDDkeeper")


def ensure_data_dir():
    d = data_dir()
    os.makedirs(d, exist_ok=True)
    return d


def baseline_path():
    return os.path.join(data_dir(), "baseline.json")


def candidate_path():
    return os.path.join(data_dir(), "candidate.json")


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def accept_current_baseline():
    ensure_data_dir()
    disks = scan_disks()
    data = {
        "accepted_at": datetime.now().isoformat(timespec="seconds"),
        "disks": disks,
    }
    save_json(baseline_path(), data)
    return data


def accept_baseline_from_list(disks):
    ensure_data_dir()
    data = {
        "accepted_at": datetime.now().isoformat(timespec="seconds"),
        "disks": list(disks) if isinstance(disks, list) else [],
    }
    save_json(baseline_path(), data)
    return data


def capture_candidate_baseline():
    ensure_data_dir()
    disks = scan_disks()
    data = {
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "disks": disks,
    }
    save_json(candidate_path(), data)
    return data


def compare_with_baseline():
    bl = load_json(baseline_path())
    if not bl or not isinstance(bl, dict) or "disks" not in bl:
        return {"error": "no_baseline"}
    current = scan_disks()
    base_map = {str(d.get("id")): d for d in bl.get("disks", [])}
    curr_map = {str(d.get("id")): d for d in current}
    added = [curr_map[k] for k in curr_map.keys() if k not in base_map]
    removed = [base_map[k] for k in base_map.keys() if k not in curr_map]
    return {
        "baseline_accepted_at": bl.get("accepted_at"),
        "baseline_count": len(base_map),
        "current_count": len(curr_map),
        "added": added,
        "removed": removed,
    }


def _print_json(obj, pretty=False):
    if pretty:
        print(json.dumps(obj, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))


# ---------------- SMTP config and secure password (DPAPI) -----------------

def config_path():
    return os.path.join(data_dir(), "config.json")


def portable_settings_path():
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "settings.json")


def overlay_portable_settings(cfg: dict) -> dict:
    try:
        p = load_json(portable_settings_path())
    except Exception:
        p = None
    if not isinstance(p, dict):
        return cfg
    local_exists = os.path.exists(config_path())
    psmtp = p.get("smtp") if isinstance(p.get("smtp"), dict) else {}
    if psmtp:
        for k in ["host", "security", "user", "from", "no_auth"]:
            if k in psmtp and not cfg["smtp"].get(k):
                cfg["smtp"][k] = psmtp.get(k)
        if "port" in psmtp and cfg["smtp"].get("port") in (None, ""):
            try:
                cfg["smtp"]["port"] = int(psmtp.get("port")) if psmtp.get("port") is not None and str(psmtp.get("port")).strip() != "" else None
            except Exception:
                pass
        rec = psmtp.get("recipients")
        if (not cfg["smtp"].get("recipients")) and rec is not None:
            if isinstance(rec, str):
                cfg["smtp"]["recipients"] = _parse_recipients(rec)
            elif isinstance(rec, list):
                cfg["smtp"]["recipients"] = [str(x).strip() for x in rec][:10]
        plain = p.get("smtp_password_plain") or psmtp.get("password_plain")
        if plain and not cfg.get("smtp_password_enc"):
            try:
                cfg["smtp_password_enc"] = _dpapi_protect(str(plain))
            except Exception:
                pass
    psched = p.get("schedule") if isinstance(p.get("schedule"), dict) else {}
    if psched and not local_exists:
        if isinstance(psched.get("every"), str):
            cfg["schedule"]["every_minutes"] = _parse_every_to_minutes(psched.get("every"))
        elif psched.get("every_minutes") is not None:
            try:
                cfg["schedule"]["every_minutes"] = int(psched.get("every_minutes"))
            except Exception:
                pass
    return cfg


def load_config():
    cfg = load_json(config_path())
    if not isinstance(cfg, dict):
        return {"smtp": {"host": None, "port": None, "security": "starttls", "user": None, "from": None, "recipients": [], "no_auth": False}, "smtp_password_enc": None, "schedule": {"mode": "interval", "every_minutes": 180, "time": "00:00", "dow": [], "dom": []}}
    if "smtp" not in cfg or not isinstance(cfg["smtp"], dict):
        cfg["smtp"] = {"host": None, "port": None, "security": "starttls", "user": None, "from": None, "recipients": [], "no_auth": False}
    cfg.setdefault("smtp_password_enc", None)
    if "schedule" not in cfg or not isinstance(cfg["schedule"], dict):
        cfg["schedule"] = {"mode": "interval", "every_minutes": 180, "time": "00:00", "dow": [], "dom": []}
    cfg["schedule"].setdefault("mode", "interval")
    cfg["schedule"].setdefault("every_minutes", 180)
    cfg["schedule"].setdefault("time", "00:00")
    cfg["schedule"].setdefault("dow", [])
    cfg["schedule"].setdefault("dom", [])
    # Overlay portable settings (settings.json next to EXE/script), if present
    cfg = overlay_portable_settings(cfg)
    return cfg


def export_portable_settings(include_password: bool = False):
    cfg = load_config()
    data = {
        "smtp": {
            "host": cfg.get("smtp", {}).get("host"),
            "port": cfg.get("smtp", {}).get("port"),
            "security": cfg.get("smtp", {}).get("security"),
            "user": cfg.get("smtp", {}).get("user"),
            "from": cfg.get("smtp", {}).get("from"),
            "recipients": cfg.get("smtp", {}).get("recipients", [])[:10],
            "no_auth": cfg.get("smtp", {}).get("no_auth", False),
        },
        "schedule": {
            "mode": cfg.get("schedule", {}).get("mode", "interval"),
            "every_minutes": cfg.get("schedule", {}).get("every_minutes", 180),
            "time": cfg.get("schedule", {}).get("time", "00:00"),
            "dow": cfg.get("schedule", {}).get("dow", []),
            "dom": cfg.get("schedule", {}).get("dom", []),
        },
    }
    if include_password and cfg.get("smtp_password_enc"):
        try:
            plain = _dpapi_unprotect(cfg.get("smtp_password_enc"))
            if plain:
                data["smtp_password_plain"] = plain
        except Exception:
            pass
    path = portable_settings_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def import_portable_settings(overwrite: bool = False, include_password: bool = False):
    base = portable_settings_path()
    if not os.path.exists(base):
        return {"error": "settings_not_found", "path": base}
    try:
        with open(base, "r", encoding="utf-8") as f:
            p = json.load(f)
    except Exception as e:
        return {"error": "invalid_settings", "path": base, "details": str(e)}
    cfg = load_config()
    if overwrite and isinstance(p, dict):
        psmtp = p.get("smtp") if isinstance(p.get("smtp"), dict) else {}
        if psmtp:
            for k in ["host", "security", "user", "from", "no_auth"]:
                if k in psmtp:
                    cfg["smtp"][k] = psmtp.get(k)
            if "port" in psmtp:
                try:
                    cfg["smtp"]["port"] = int(psmtp.get("port")) if psmtp.get("port") is not None and str(psmtp.get("port")).strip() != "" else None
                except Exception:
                    pass
            rec = psmtp.get("recipients")
            if rec is not None:
                if isinstance(rec, str):
                    cfg["smtp"]["recipients"] = _parse_recipients(rec)
                elif isinstance(rec, list):
                    cfg["smtp"]["recipients"] = [str(x).strip() for x in rec][:10]
            # Password import is optional and disabled by default
            plain = p.get("smtp_password_plain") or psmtp.get("password_plain")
            if include_password and plain:
                try:
                    cfg["smtp_password_enc"] = _dpapi_protect(str(plain))
                except Exception:
                    pass
        psched = p.get("schedule") if isinstance(p.get("schedule"), dict) else {}
        if psched:
            if isinstance(psched.get("every"), str):
                cfg["schedule"]["every_minutes"] = _parse_every_to_minutes(psched.get("every"))
                cfg["schedule"]["mode"] = "interval"
            elif psched.get("every_minutes") is not None:
                try:
                    cfg["schedule"]["every_minutes"] = int(psched.get("every_minutes"))
                    cfg["schedule"]["mode"] = "interval"
                except Exception:
                    pass
            mode = psched.get("mode")
            if mode in ("interval", "calendar"):
                cfg["schedule"]["mode"] = mode
            if psched.get("time") is not None:
                cfg["schedule"]["time"] = _normalize_time(psched.get("time"))
            if isinstance(psched.get("dow"), list):
                cfg["schedule"]["dow"] = _normalize_dow(psched.get("dow"))
            if isinstance(psched.get("dom"), list):
                cfg["schedule"]["dom"] = _normalize_dom(psched.get("dom"))
    save_config(cfg)
    return {"status": "ok", "path": base, "overwritten": bool(overwrite), "password_imported": bool(include_password and (p.get("smtp_password_plain") or (isinstance(p.get("smtp"), dict) and p.get("smtp", {}).get("password_plain"))))}


def save_config(cfg):
    ensure_data_dir()
    save_json(config_path(), cfg)


class DATA_BLOB(Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", POINTER(c_byte))]


def _dpapi_protect(plaintext: str) -> str:
    if plaintext is None:
        return None
    data = plaintext.encode("utf-8")
    blob_in = DATA_BLOB()
    blob_in.cbData = len(data)
    buf = create_string_buffer(data)
    blob_in.pbData = cast(buf, POINTER(c_byte))
    blob_out = DATA_BLOB()
    CRYPTPROTECT_UI_FORBIDDEN = 0x01
    if not windll.crypt32.CryptProtectData(byref(blob_in), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(blob_out)):
        raise OSError("CryptProtectData failed")
    try:
        enc = bytes((blob_out.pbData[i] for i in range(blob_out.cbData)))
        return base64.b64encode(enc).decode("ascii")
    finally:
        windll.kernel32.LocalFree(blob_out.pbData)


def _dpapi_unprotect(cipher_b64: str) -> str:
    if not cipher_b64:
        return None
    enc = base64.b64decode(cipher_b64)
    blob_in = DATA_BLOB()
    buf = create_string_buffer(enc)
    blob_in.cbData = len(enc)
    blob_in.pbData = cast(buf, POINTER(c_byte))
    blob_out = DATA_BLOB()
    CRYPTPROTECT_UI_FORBIDDEN = 0x01
    if not windll.crypt32.CryptUnprotectData(byref(blob_in), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(blob_out)):
        raise OSError("CryptUnprotectData failed")
    try:
        dec = bytes((blob_out.pbData[i] for i in range(blob_out.cbData)))
        return dec.decode("utf-8", errors="replace")
    finally:
        windll.kernel32.LocalFree(blob_out.pbData)


def _parse_recipients(s: str):
    if not s:
        return []
    parts = re.split(r"[;,]", s)
    rec = []
    for p in parts:
        v = p.strip()
        if v and v not in rec:
            rec.append(v)
    return rec[:10]


def set_smtp_config(host, port, security, user, from_addr, recipients_csv, no_auth):
    cfg = load_config()
    smtp = cfg["smtp"]
    if host is not None:
        smtp["host"] = host
    if port is not None:
        smtp["port"] = int(port)
    if security is not None:
        smtp["security"] = security
    if user is not None:
        smtp["user"] = user
    if from_addr is not None:
        smtp["from"] = from_addr
    if recipients_csv is not None:
        smtp["recipients"] = _parse_recipients(recipients_csv)
    if no_auth is not None:
        smtp["no_auth"] = bool(no_auth)
    save_config(cfg)
    return cfg


def set_smtp_password_interactive():
    pwd1 = getpass.getpass("Enter SMTP password: ")
    pwd2 = getpass.getpass("Confirm SMTP password: ")
    if pwd1 != pwd2:
        raise ValueError("Passwords do not match")
    enc = _dpapi_protect(pwd1)
    cfg = load_config()
    cfg["smtp_password_enc"] = enc
    save_config(cfg)
    return True


def set_smtp_password_gui(prompt_title: str = "HDDkeeper"):
    try:
        import tkinter as tk
        from tkinter import simpledialog, messagebox
    except Exception:
        return {"error": "tkinter_not_available"}
    root = tk.Tk(); root.withdraw()
    pwd1 = simpledialog.askstring(prompt_title, "Enter SMTP password:", show='*')
    if pwd1 is None:
        return {"status": "cancel"}
    pwd2 = simpledialog.askstring(prompt_title, "Confirm SMTP password:", show='*')
    if pwd2 is None:
        return {"status": "cancel"}
    if pwd1 != pwd2:
        messagebox.showerror(prompt_title, "Passwords do not match")
        return {"error": "mismatch"}
    try:
        enc = _dpapi_protect(pwd1)
        cfg = load_config()
        cfg["smtp_password_enc"] = enc
        save_config(cfg)
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}


def _open_smtp(smtp_cfg, password):
    host = smtp_cfg.get("host")
    port = int(smtp_cfg.get("port") or 0)
    security = (smtp_cfg.get("security") or "starttls").lower()
    user = smtp_cfg.get("user")
    ctx = ssl.create_default_context()
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port or 465, context=ctx, timeout=30)
    else:
        server = smtplib.SMTP(host, port or 587, timeout=30)
        server.ehlo()
        if security == "starttls":
            server.starttls(context=ctx)
            server.ehlo()
    # Login only if explicitly allowed and server supports AUTH
    if not smtp_cfg.get("no_auth") and user:
        features = getattr(server, 'esmtp_features', {}) or {}
        if 'auth' in features:
            server.login(user, password or "")
    return server


def _format_bytes(n):
    try:
        n = int(n)
    except Exception:
        return str(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _compose_diff_email(diff):
    host = os.environ.get("COMPUTERNAME") or platform.node()
    subject = f"HDDkeeper: disks change on {host}"
    lines = []
    lines.append(f"Host: {host}")
    lines.append(f"Baseline accepted at: {diff.get('baseline_accepted_at')}")
    lines.append(f"Baseline count: {diff.get('baseline_count')} -> Current: {diff.get('current_count')}")
    lines.append("")
    if diff.get("added"):
        lines.append("Added disks:")
        for d in diff["added"]:
            lines.append(f"  - {d.get('serial')} | {d.get('model')} | {_format_bytes(d.get('size_bytes'))} | {d.get('bus')} (src={d.get('source')})")
        lines.append("")
    if diff.get("removed"):
        lines.append("Removed disks:")
        for d in diff["removed"]:
            lines.append(f"  - {d.get('serial')} | {d.get('model')} | {_format_bytes(d.get('size_bytes'))} | {d.get('bus')} (src={d.get('source')})")
        lines.append("")
    body = "\n".join(lines) or "No changes detected."
    return subject, body


def send_email_diff(diff, is_test=False):
    cfg = load_config()
    smtp_cfg = cfg.get("smtp", {})
    if not smtp_cfg.get("host") or not smtp_cfg.get("from") or not smtp_cfg.get("recipients"):
        return {"error": "smtp_not_configured"}
    password = None
    if cfg.get("smtp_password_enc"):
        try:
            password = _dpapi_unprotect(cfg["smtp_password_enc"])
        except Exception:
            password = None
    subject, body = ("HDDkeeper test email", "This is a test email from HDDkeeper.") if is_test else _compose_diff_email(diff)
    msg = EmailMessage()
    msg["From"] = smtp_cfg.get("from")
    msg["To"] = ", ".join(smtp_cfg.get("recipients", [])[:10])
    msg["Subject"] = subject
    msg.set_content(body)
    with _open_smtp(smtp_cfg, password) as s:
        s.send_message(msg)
    return {"status": "sent", "to": smtp_cfg.get("recipients", [])[:10]}


def notify_if_diff(pretty=False):
    diff = compare_with_baseline()
    if diff.get("error") == "no_baseline":
        return diff
    # Always send if there is any change (repeat allowed by requirements)
    if diff.get("added") or diff.get("removed"):
        try:
            send_email_diff(diff, is_test=False)
            diff["notified"] = True
        except Exception as e:
            diff["notify_error"] = str(e)
    else:
        diff["notified"] = False
    return diff


# ---------------- Scheduler (Task Scheduler) -----------------

def _parse_every_to_minutes(s: str) -> int:
    if not s:
        return 180
    t = s.strip().lower()
    m = re.match(r"^(\d+)\s*([smhd]?)$", t)
    if not m:
        # try plain int minutes
        try:
            return max(1, int(t))
        except Exception:
            return 180
    val = int(m.group(1))
    unit = m.group(2) or "m"
    if unit == "s":
        return max(1, (val + 59) // 60)
    if unit == "m":
        return max(1, val)
    if unit == "h":
        return max(1, val * 60)
    if unit == "d":
        return max(1, val * 1440)
    return 180


def set_schedule_config_every(every_str: str):
    minutes = _parse_every_to_minutes(every_str)
    cfg = load_config()
    cfg["schedule"]["mode"] = "interval"
    cfg["schedule"]["every_minutes"] = minutes
    save_config(cfg)
    return cfg


def _normalize_time(s: str) -> str:
    m = re.match(r"^\s*(\d{1,2})\s*:\s*(\d{2})\s*$", str(s or ""))
    if not m:
        return "00:00"
    h = max(0, min(23, int(m.group(1))))
    mi = max(0, min(59, int(m.group(2))))
    return f"{h:02d}:{mi:02d}"


def _normalize_dow(xs) -> list:
    if not isinstance(xs, list):
        return []
    allowed = {"MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"}
    out = []
    for x in xs:
        t = str(x or "").strip().upper()
        # Normalize Russian/short forms if any
        mapping = {
            "ПН": "MON", "ВТ": "TUE", "СР": "WED", "ЧТ": "THU", "ПТ": "FRI", "СБ": "SAT", "ВС": "SUN",
            "MONDAY": "MON", "TUESDAY": "TUE", "WEDNESDAY": "WED", "THURSDAY": "THU", "FRIDAY": "FRI", "SATURDAY": "SAT", "SUNDAY": "SUN",
        }
        if t in mapping:
            t = mapping[t]
        if len(t) > 3:
            t = t[:3]
        if t in allowed and t not in out:
            out.append(t)
    return out


def _normalize_dom(xs) -> list:
    if not isinstance(xs, list):
        return []
    out = []
    for x in xs:
        try:
            v = int(str(x).strip())
            if 1 <= v <= 31 and v not in out:
                out.append(v)
        except Exception:
            pass
    return out


def set_schedule_time_config(time_str: str, dow_csv: str, dom_csv: str):
    cfg = load_config()
    cfg["schedule"]["mode"] = "calendar"
    cfg["schedule"]["time"] = _normalize_time(time_str)
    dows = []
    if dow_csv and str(dow_csv).strip():
        dows = [t.strip() for t in re.split(r"[;,\s]+", str(dow_csv)) if t.strip()]
    cfg["schedule"]["dow"] = _normalize_dow(dows)
    doms = []
    if dom_csv and str(dom_csv).strip():
        try:
            doms = [int(t.strip()) for t in re.split(r"[;,\s]+", str(dom_csv)) if t.strip()]
        except Exception:
            doms = []
    cfg["schedule"]["dom"] = _normalize_dom(doms)
    save_config(cfg)
    return cfg


def _ensure_self_copy_py() -> str:
    ensure_data_dir()
    src = os.path.abspath(__file__)
    dst = os.path.join(data_dir(), "hddkeeper.py")
    try:
        if not os.path.exists(dst) or os.path.getmtime(src) > os.path.getmtime(dst):
            shutil.copy2(src, dst)
    except Exception:
        # best-effort, ignore copy failures
        pass
    return dst


def _self_targets():
    base = data_dir()
    return (
        os.path.join(base, "HDDkeeper.exe"),
        os.path.join(base, "HDDkeeperTray.exe"),
        os.path.join(base, "hddkeeper.py"),
    )


def _ensure_self_deployed() -> str:
    """Copy current binary/script into ProgramData and return target path.
    If running as PyInstaller EXE, copies EXE to HDDkeeper.exe (or HDDkeeperTray.exe if name contains 'tray').
    If running as script, copies .py and returns its path.
    """
    ensure_data_dir()
    main_t, tray_t, py_t = _self_targets()
    try:
        if getattr(sys, "frozen", False):
            src = sys.executable
            name = os.path.basename(src).lower()
            target = tray_t if "tray" in name else main_t
            if not os.path.exists(target) or os.path.getmtime(src) > os.path.getmtime(target):
                shutil.copy2(src, target)
            return target
        else:
            src = os.path.abspath(__file__)
            if not os.path.exists(py_t) or os.path.getmtime(src) > os.path.getmtime(py_t):
                shutil.copy2(src, py_t)
            return py_t
    except Exception:
        # Fallback to original behavior
        return _ensure_self_copy_py()


def _get_pythonw():
    exe = sys.executable or ""
    if exe:
        cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(cand):
            return cand
    for n in ("pyw.exe", "pythonw.exe", "pyw"):
        p = which(n)
        if p:
            return p
    return sys.executable or "python"


def _schtasks_create_or_update(name: str, tr_cmd: str, schedule_type: str, mo: str = None, onstart: bool = False):
    args = ["schtasks", "/Create", "/TN", name, "/TR", tr_cmd, "/F", "/RU", "SYSTEM"]
    if onstart:
        args += ["/SC", "ONSTART"]
    else:
        args += ["/SC", schedule_type]
        if mo is not None:
            args += ["/MO", str(mo)]
    rc, out, err = _run(args)
    return rc, out, err


def _launch_gui():
    try:
        main_t, tray_t, py_t = _self_targets()
        if os.path.exists(main_t):
            try:
                subprocess.Popen([main_t])
                return True
            except Exception:
                pass
        if getattr(sys, "frozen", False):
            try:
                subprocess.Popen([sys.executable, "--gui"])
                return True
            except Exception:
                pass
        py = _get_pythonw()
        try:
            subprocess.Popen([py, os.path.abspath(__file__), "--gui"])
            return True
        except Exception:
            return False
    except Exception:
        return False

def _tray_is_running():
    if os.name != "nt":
        return False
    try:
        # SYNCHRONIZE | MUTEX_MODIFY_STATE
        access = 0x00100000 | 0x0001
        name = "Local\\HDDkeeperTrayMutex"
        h = windll.kernel32.OpenMutexW(access, False, name)
        if h:
            try:
                windll.kernel32.CloseHandle(h)
            except Exception:
                pass
            return True
    except Exception:
        pass
    return False

def _launch_tray():
    try:
        if _tray_is_running():
            return True
        main_t, tray_t, py_t = _self_targets()
        if os.path.exists(tray_t):
            try:
                subprocess.Popen([tray_t])
                return True
            except Exception:
                pass
        if getattr(sys, "frozen", False):
            try:
                subprocess.Popen([sys.executable, "--tray"])
                return True
            except Exception:
                pass
        py = _get_pythonw()
        try:
            subprocess.Popen([py, os.path.abspath(__file__), "--tray"])
            return True
        except Exception:
            return False
    except Exception:
        return False

def install_tasks():
    cfg = load_config()
    schedule = cfg.get("schedule", {})
    target_path = _ensure_self_deployed()
    if target_path.lower().endswith(".exe"):
        tr_cmd = f'"{target_path}" --notify-if-diff'
    else:
        py = sys.executable or "python"
        tr_cmd = f'"{py}" "{target_path}" --notify-if-diff'

    mode = schedule.get("mode", "interval")
    results = {}

    def _del_task(name: str):
        try:
            return _run(["schtasks", "/Delete", "/TN", name, "/F"])  # ignore rc
        except Exception as _:
            return (1, "", "")

    if mode == "calendar":
        # Remove periodic task if switching modes
        _del_task("HDDkeeper Periodic Scan")
        # Weekly
        dow = schedule.get("dow") or []
        time_s = _normalize_time(schedule.get("time"))
        if dow:
            args = [
                "schtasks", "/Create", "/TN", "HDDkeeper Weekly Scan",
                "/TR", tr_cmd, "/F", "/RU", "SYSTEM",
                "/SC", "WEEKLY", "/D", ",".join(dow), "/ST", time_s,
            ]
            rw = _run(args)
            results["weekly"] = {"rc": rw[0], "out": rw[1], "err": rw[2], "dow": dow, "time": time_s}
        else:
            # Ensure previous weekly task is removed if no days selected
            _del_task("HDDkeeper Weekly Scan")
            results["weekly"] = {"rc": 0}
        # Monthly
        dom = schedule.get("dom") or []
        if dom:
            args = [
                "schtasks", "/Create", "/TN", "HDDkeeper Monthly Scan",
                "/TR", tr_cmd, "/F", "/RU", "SYSTEM",
                "/SC", "MONTHLY", "/D", ",".join(str(x) for x in dom), "/ST", time_s,
            ]
            rm = _run(args)
            results["monthly"] = {"rc": rm[0], "out": rm[1], "err": rm[2], "dom": dom, "time": time_s}
        else:
            _del_task("HDDkeeper Monthly Scan")
            results["monthly"] = {"rc": 0}
    else:
        # interval mode
        # Remove calendar tasks if switching modes
        _del_task("HDDkeeper Weekly Scan")
        _del_task("HDDkeeper Monthly Scan")
        minutes = int(schedule.get("every_minutes", 180) or 180)
        if minutes >= 1440 and minutes % 1440 == 0:
            sc = "DAILY"
            mo = minutes // 1440
        elif minutes % 60 == 0:
            sc = "HOURLY"
            mo = minutes // 60
        else:
            sc = "MINUTE"
            mo = minutes
        r1 = _schtasks_create_or_update("HDDkeeper Periodic Scan", tr_cmd, sc, mo=mo, onstart=False)
        results["periodic"] = {"rc": r1[0], "out": r1[1], "err": r1[2], "every_minutes": minutes, "sc": sc, "mo": mo}
        # Start immediately after creating interval rule
        try:
            _run(["schtasks", "/Run", "/TN", "HDDkeeper Periodic Scan"])  # fire first run
        except Exception:
            pass

    # Startup and Tray tasks are common
    r2 = _schtasks_create_or_update("HDDkeeper Startup Scan", tr_cmd, schedule_type="ONSTART", mo=None, onstart=True)
    tray = install_tray_task()
    results["startup"] = {"rc": r2[0], "out": r2[1], "err": r2[2]}
    results["tray"] = {"rc": tray[0], "out": tray[1], "err": tray[2]}
    return results


def uninstall_tasks():
    results = {}
    for name in ["HDDkeeper Periodic Scan", "HDDkeeper Startup Scan", "HDDkeeper Tray", "HDDkeeper Weekly Scan", "HDDkeeper Monthly Scan"]:
        rc, out, err = _run(["schtasks", "/Delete", "/TN", name, "/F"])
        results[name] = {"rc": rc, "out": out, "err": err}
    return results


def run_now_tasks():
    names = [
        "HDDkeeper Periodic Scan",
        "HDDkeeper Weekly Scan",
        "HDDkeeper Monthly Scan",
    ]
    started = []
    attempts = []
    errors = {}
    for n in names:
        attempts.append(n)
        try:
            rc, out, err = _run(["schtasks", "/Run", "/TN", n])
        except Exception as e:
            rc, out, err = 1, "", str(e)
        if rc == 0:
            started.append(n)
        else:
            errors[n] = {"rc": rc, "out": out, "err": err}
    if started:
        return {"status": "ok", "started": started, "attempted": attempts, "errors": errors}
    try:
        diff = notify_if_diff()
    except Exception as e:
        diff = {"error": str(e)}
    return {"status": "fallback", "started": started, "attempted": attempts, "errors": errors, "direct": diff}


def install_tray_task():
    target_path = _ensure_self_deployed()
    main_t, tray_t, py_t = _self_targets()
    if os.path.exists(tray_t):
        tr_cmd = f'"{tray_t}"'
    elif target_path.lower().endswith(".exe"):
        tr_cmd = f'"{target_path}" --tray'
    else:
        py = _get_pythonw()
        tr_cmd = f'"{py}" "{target_path}" --tray'
    args = [
        "schtasks", "/Create", "/TN", "HDDkeeper Tray",
        "/TR", tr_cmd, "/F",
        "/SC", "ONLOGON",
        "/IT",
        "/RL", "LIMITED",
    ]
    rc, out, err = _run(args)
    return rc, out, err


def tray_main():
    try:
        import tkinter as tk
        from tkinter import simpledialog, messagebox
    except Exception:
        print(json.dumps({"error": "tkinter_not_available"}))
        return 1
    try:
        import pystray
        from PIL import Image, ImageDraw
    except Exception:
        root = tk.Tk(); root.withdraw()
        messagebox.showerror("HDDkeeper", "pystray/Pillow not installed. Install with: py -3 -m pip install pystray pillow")
        return 1

    # Single-instance for tray (per session)
    hmutex = None
    if os.name == "nt":
        try:
            name = "Local\\HDDkeeperTrayMutex"
            h = windll.kernel32.CreateMutexW(None, False, name)
            if h:
                err = windll.kernel32.GetLastError()
                if err == 183:  # ERROR_ALREADY_EXISTS
                    try:
                        windll.kernel32.CloseHandle(h)
                    except Exception:
                        pass
                    return 0
                hmutex = h
        except Exception:
            hmutex = None

    cfg = load_config()

    root = tk.Tk()
    root.withdraw()

    def mkimg():
        size = 64
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.ellipse((8, 8, size-8, size-8), fill=(0, 136, 255, 255))
        d.ellipse((18, 18, size-18, size-18), fill=(255, 255, 255, 255))
        d.ellipse((26, 26, size-26, size-26), fill=(0, 136, 255, 255))
        return img

    def show(msg):
        messagebox.showinfo("HDDkeeper", msg)

    def do_open_gui(icon, item):
        ok = _launch_gui()
        if not ok:
            show("Unable to start GUI")

    def do_accept(icon, item):
        bl = accept_current_baseline()
        show(f"Baseline accepted: {bl.get('accepted_at')}\nCount: {len(bl.get('disks', []))}")

    def do_scan(icon, item):
        diff = notify_if_diff()
        if diff.get("error"):
            show("No baseline. Accept baseline first.")
            return
        added = len(diff.get("added", []))
        removed = len(diff.get("removed", []))
        sent = diff.get("notified")
        show(f"Scan done. Added: {added}, Removed: {removed}. Email sent: {sent}.")

    def do_test_email(icon, item):
        try:
            res = send_email_diff({}, is_test=True)
            if res.get("status") == "sent":
                show("Test email sent.")
            else:
                show(f"Email error: {res}")
        except Exception as e:
            show(f"Email error: {e}")

    def do_set_schedule(icon, item):
        val = simpledialog.askstring("HDDkeeper", "Interval (e.g., 3h, 180m, 1d):")
        if not val:
            return
        cfg = set_schedule_config_every(val)
        install_tasks()
        show(f"Schedule set to {cfg.get('schedule', {}).get('every_minutes')} minutes.")

    def do_quit(icon, item):
        icon.stop()
        try:
            root.destroy()
        except Exception:
            pass
        try:
            if hmutex:
                windll.kernel32.CloseHandle(hmutex)
        except Exception:
            pass

    menu = pystray.Menu(
        pystray.MenuItem("Open GUI", do_open_gui),
        pystray.MenuItem("Accept baseline", do_accept),
        pystray.MenuItem("Scan now", do_scan),
        pystray.MenuItem("Test email", do_test_email),
        pystray.MenuItem("Set schedule", do_set_schedule),
        pystray.MenuItem("Quit", do_quit),
    )
    icon = pystray.Icon("HDDkeeper", mkimg(), "HDDkeeper", menu)
    icon.run()
    try:
        if hmutex:
            windll.kernel32.CloseHandle(hmutex)
    except Exception:
        pass
    return 0


def gui_main():
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
    except Exception:
        print(json.dumps({"error": "tkinter_not_available"}))
        return 1

    cfg = load_config()

    root = tk.Tk()
    root.title("HDDkeeper")
    root.geometry("460x420")

    # Vars
    host_v = tk.StringVar(value=str(cfg.get("smtp", {}).get("host") or ""))
    port_v = tk.StringVar(value=str(cfg.get("smtp", {}).get("port") or ""))
    sec_v = tk.StringVar(value=str(cfg.get("smtp", {}).get("security") or "starttls"))
    user_v = tk.StringVar(value=str(cfg.get("smtp", {}).get("user") or ""))
    from_v = tk.StringVar(value=str(cfg.get("smtp", {}).get("from") or ""))
    rec_v = tk.StringVar(value=", ".join(cfg.get("smtp", {}).get("recipients", [])))
    noauth_v = tk.BooleanVar(value=bool(cfg.get("smtp", {}).get("no_auth", False)))
    mode_v = tk.StringVar(value=str(cfg.get("schedule", {}).get("mode", "interval")))
    every_v = tk.StringVar(value=f"{cfg.get('schedule', {}).get('every_minutes', 180)}m")
    time_v = tk.StringVar(value=str(cfg.get("schedule", {}).get("time", "00:00")))
    dow_vars = {c: tk.BooleanVar(value=(c in (cfg.get('schedule', {}).get('dow', [])))) for c in ("MON","TUE","WED","THU","FRI","SAT","SUN")}
    dom_v = tk.StringVar(value=", ".join(str(x) for x in (cfg.get('schedule', {}).get('dom', []))))

    pad = {"padx": 6, "pady": 4, "sticky": "we"}
    root.columnconfigure(0, weight=1)

    # Bold titles for main blocks
    style = ttk.Style()
    try:
        style.configure("Bold.TLabelframe.Label", font=("TkDefaultFont", 10, "bold"))
    except Exception:
        pass

    frm_mail = ttk.LabelFrame(root, text="Mail settings", style="Bold.TLabelframe")
    frm_tasks = ttk.LabelFrame(root, text="Task schedule", style="Bold.TLabelframe")
    frm_export = ttk.LabelFrame(root, text="Export / Import", style="Bold.TLabelframe")
    frm_actions = ttk.Frame(root)

    frm_mail.grid(row=0, column=0, sticky="we", padx=8, pady=(8, 4))
    frm_tasks.grid(row=1, column=0, sticky="we", padx=8, pady=4)
    frm_export.grid(row=2, column=0, sticky="we", padx=8, pady=4)
    frm_actions.grid(row=3, column=0, sticky="we", padx=8, pady=(4, 8))

    frm_mail.columnconfigure(1, weight=1)
    frm_tasks.columnconfigure(1, weight=1)
    frm_export.columnconfigure(0, weight=1)
    frm_export.columnconfigure(1, weight=1)
    frm_export.columnconfigure(2, weight=1)
    frm_actions.columnconfigure(0, weight=1)
    frm_actions.columnconfigure(1, weight=1)

    row = 0
    ttk.Label(frm_mail, text="SMTP host").grid(row=row, column=0, **pad)
    ttk.Entry(frm_mail, textvariable=host_v).grid(row=row, column=1, columnspan=3, **pad)
    row += 1
    ttk.Label(frm_mail, text="SMTP port").grid(row=row, column=0, **pad)
    ttk.Entry(frm_mail, textvariable=port_v).grid(row=row, column=1, **pad)
    ttk.Label(frm_mail, text="Security").grid(row=row, column=2, **pad)
    ttk.Combobox(frm_mail, textvariable=sec_v, values=["none", "starttls", "ssl"], state="readonly").grid(row=row, column=3, **pad)
    row += 1
    ttk.Label(frm_mail, text="User").grid(row=row, column=0, **pad)
    ttk.Entry(frm_mail, textvariable=user_v).grid(row=row, column=1, columnspan=3, **pad)
    row += 1
    ttk.Label(frm_mail, text="From").grid(row=row, column=0, **pad)
    ttk.Entry(frm_mail, textvariable=from_v).grid(row=row, column=1, columnspan=3, **pad)
    row += 1
    ttk.Label(frm_mail, text="Recipients").grid(row=row, column=0, **pad)
    ttk.Entry(frm_mail, textvariable=rec_v).grid(row=row, column=1, columnspan=2, **pad)
    ttk.Checkbutton(frm_mail, text="No AUTH", variable=noauth_v).grid(row=row, column=3, **pad)
    row += 1

    def ui_save_smtp():
        cfg = set_smtp_config(host_v.get() or None,
                               int(port_v.get()) if port_v.get().strip() else None,
                               sec_v.get(),
                               user_v.get() or None,
                               from_v.get() or None,
                               rec_v.get() or None,
                               noauth_v.get())
        messagebox.showinfo("HDDkeeper", "SMTP settings saved")

    def ui_set_pwd():
        res = set_smtp_password_gui()
        if res.get("status") == "ok":
            messagebox.showinfo("HDDkeeper", "Password saved")
        elif res.get("status") == "cancel":
            pass
        else:
            messagebox.showerror("HDDkeeper", f"Error: {res}")

    def ui_test_email():
        try:
            r = send_email_diff({}, is_test=True)
            if r.get("status") == "sent":
                messagebox.showinfo("HDDkeeper", "Test email sent")
            else:
                messagebox.showerror("HDDkeeper", f"Email error: {r}")
        except Exception as e:
            messagebox.showerror("HDDkeeper", f"Email error: {e}")

    def ui_accept():
        frames = ["|", "/", "-", "\\"]
        idx = {"i": 0, "run": True}
        orig = accept_btn.cget("text") if 'accept_btn' in locals() else "Accept baseline"

        def spin():
            if idx["run"]:
                try:
                    accept_btn.config(text=f"Scanning {frames[idx['i']]}")
                except Exception:
                    pass
                idx["i"] = (idx["i"] + 1) % len(frames)
                root.after(120, spin)

        res = {"disks": None, "err": None}

        def worker():
            try:
                res["disks"] = scan_disks()
            except Exception as e:
                res["err"] = str(e)
            finally:
                root.after(0, done)

        def done():
            idx["run"] = False
            try:
                accept_btn.config(text=orig)
                accept_btn.config(state="normal")
            except Exception:
                pass
            if res["err"]:
                messagebox.showerror("HDDkeeper", f"Scan error: {res['err']}")
                return
            disks = res["disks"] or []
            # Load baseline to mark which disks are already accepted and which are missing
            bl = load_json(baseline_path())
            base_map = {}
            if isinstance(bl, dict) and isinstance(bl.get("disks"), list):
                try:
                    base_map = {str(d.get("id")): d for d in bl.get("disks", [])}
                except Exception:
                    base_map = {}
            win = tk.Toplevel(root)
            win.title("Accept baseline")
            win.geometry("700x420")
            win.transient(root)
            try:
                win.grab_set()
            except Exception:
                pass
            cols = ("sel", "serial", "model", "size", "bus", "source")
            tree = ttk.Treeview(win, columns=cols, show="headings")
            tree.tag_configure('missing', foreground='#888')
            sort_state = {c: False for c in cols}

            def parse_size(s):
                m = re.match(r"\s*([0-9]+(?:\.[0-9]+)?)\s*(B|KB|MB|GB|TB)\s*$", str(s))
                if not m:
                    return 0.0
                val = float(m.group(1))
                unit = m.group(2).upper()
                mul = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}.get(unit, 1)
                return val * mul

            def sort_by(col):
                children = list(tree.get_children(""))
                def keyfunc(item):
                    v = tree.set(item, col)
                    if col == "size":
                        return parse_size(v)
                    return str(v).lower()
                rev = sort_state.get(col, False)
                children.sort(key=keyfunc, reverse=rev)
                for n, it in enumerate(children):
                    tree.move(it, "", n)
                sort_state[col] = not rev

            tree.heading("sel", text="✓", command=lambda c="sel": sort_by(c))
            tree.heading("serial", text="Serial", command=lambda c="serial": sort_by(c))
            tree.heading("model", text="Model", command=lambda c="model": sort_by(c))
            tree.heading("size", text="Size", command=lambda c="size": sort_by(c))
            tree.heading("bus", text="Bus", command=lambda c="bus": sort_by(c))
            tree.heading("source", text="Source", command=lambda c="source": sort_by(c))
            tree.column("sel", width=40, anchor="center")
            tree.column("serial", width=170, anchor="w")
            tree.column("model", width=270, anchor="w")
            tree.column("size", width=110, anchor="center")
            tree.column("bus", width=70, anchor="center")
            tree.column("source", width=70, anchor="center")
            vsb = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=vsb.set)
            tree.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
            vsb.grid(row=0, column=1, sticky="ns", pady=8)
            win.columnconfigure(0, weight=1)
            win.rowconfigure(0, weight=1)

            data_ref = {"disks": disks, "base_map": base_map}

            def populate():
                for it in tree.get_children(""):
                    tree.delete(it)
                # Current disks
                curr = list(data_ref["disks"]) or []
                base_map = data_ref.get("base_map", {}) or {}
                curr_ids = set()
                for d in curr:
                    rid = str(d.get("id"))
                    curr_ids.add(rid)
                    in_base = rid in base_map
                    tree.insert("", "end",
                                values=(
                                    "✓" if in_base else "",
                                    d.get("serial"),
                                    d.get("model"),
                                    _format_bytes(d.get("size_bytes")),
                                    d.get("bus"),
                                    d.get("source"),
                                ))
                # Missing (in baseline but not currently present)
                for rid, bd in base_map.items():
                    if rid in curr_ids:
                        continue
                    tree.insert("", "end",
                                values=(
                                    "✓",
                                    bd.get("serial"),
                                    bd.get("model"),
                                    _format_bytes(bd.get("size_bytes")),
                                    bd.get("bus"),
                                    bd.get("source") or "baseline",
                                ),
                                tags=("missing",))

            populate()

            btns = ttk.Frame(win)
            btns.grid(row=1, column=0, columnspan=2, sticky="e", padx=8, pady=(0, 8))

            def do_rescan():
                btn_accept.config(state="disabled")
                btn_rescan.config(text="Rescan...", state="disabled")
                def w():
                    try:
                        nd = scan_disks()
                    except Exception as e:
                        nd = None
                        err = str(e)
                    else:
                        err = None
                    def finish():
                        if err:
                            messagebox.showerror("HDDkeeper", f"Scan error: {err}")
                        else:
                            data_ref["disks"] = nd or []
                            populate()
                        btn_rescan.config(text="Rescan", state="normal")
                        btn_accept.config(state="normal")
                    win.after(0, finish)
                threading.Thread(target=w, daemon=True).start()

            def do_accept_now():
                bl = accept_baseline_from_list(data_ref["disks"])
                messagebox.showinfo("HDDkeeper", f"Baseline accepted: {bl.get('accepted_at')}\nCount: {len(bl.get('disks', []))}")
                try:
                    _launch_tray()
                except Exception:
                    pass
                try:
                    win.destroy()
                except Exception:
                    pass

            def do_cancel():
                try:
                    win.destroy()
                except Exception:
                    pass

            btn_rescan = ttk.Button(btns, text="Rescan", command=do_rescan)
            btn_cancel = ttk.Button(btns, text="Cancel", command=do_cancel)
            btn_accept = ttk.Button(btns, text="Accept", command=do_accept_now)
            btn_cancel.pack(side="right", padx=(0, 6))
            btn_accept.pack(side="right")
            btn_rescan.pack(side="left")

        try:
            accept_btn.config(state="disabled")
        except Exception:
            pass
        spin()
        threading.Thread(target=worker, daemon=True).start()

    def ui_scan():
        diff = notify_if_diff()
        if diff.get("error") == "no_baseline":
            messagebox.showwarning("HDDkeeper", "No baseline. Accept baseline first.")
            return
        messagebox.showinfo("HDDkeeper", f"Added: {len(diff.get('added', []))}, Removed: {len(diff.get('removed', []))}\nEmail sent: {diff.get('notified')}")

    def ui_set_schedule():
        cfg = set_schedule_config_every(every_v.get())
        install_tasks()
        messagebox.showinfo("HDDkeeper", f"Interval: {cfg.get('schedule', {}).get('every_minutes')} minutes")

    def ui_set_schedule_calendar():
        selected_dow = [k for k, v in dow_vars.items() if v.get()]
        cfg = set_schedule_time_config(time_v.get(), ";".join(selected_dow), dom_v.get())
        install_tasks()
        messagebox.showinfo("HDDkeeper", f"Calendar: {cfg.get('schedule', {}).get('time')} DOW={','.join(cfg.get('schedule', {}).get('dow', []))} DOM={','.join(str(x) for x in cfg.get('schedule', {}).get('dom', []))}")

    def ui_install():
        r = install_tasks()
        pr = r.get('periodic', {}).get('rc')
        wr = r.get('weekly', {}).get('rc')
        mr = r.get('monthly', {}).get('rc')
        ok_sched = (pr == 0) or ((wr in (0, None)) and (mr in (0, None)))
        ok = (ok_sched and r.get('startup', {}).get('rc') == 0 and r.get('tray', {}).get('rc') == 0)
        messagebox.showinfo("HDDkeeper", f"Tasks installed: {ok}")

    def ui_uninstall():
        r = uninstall_tasks()
        messagebox.showinfo("HDDkeeper", "Tasks removed")

    def ui_export():
        p = export_portable_settings(include_password=False)
        messagebox.showinfo("HDDkeeper", f"Exported to {p}")

    def ui_export_with_pwd():
        p = export_portable_settings(include_password=True)
        messagebox.showinfo("HDDkeeper", f"Exported with password to {p}")

    def ui_import():
        r = import_portable_settings(overwrite=True)
        if r.get("status") == "ok":
            try:
                cfg2 = load_config()
                host_v.set(str(cfg2.get("smtp", {}).get("host") or ""))
                pval = cfg2.get("smtp", {}).get("port")
                port_v.set("") if (pval is None or str(pval).strip() == "") else port_v.set(str(pval))
                sec_v.set(str(cfg2.get("smtp", {}).get("security") or "starttls"))
                user_v.set(str(cfg2.get("smtp", {}).get("user") or ""))
                from_v.set(str(cfg2.get("smtp", {}).get("from") or ""))
                recs = cfg2.get("smtp", {}).get("recipients", [])
                if not isinstance(recs, list):
                    recs = []
                rec_v.set(", ".join([str(x) for x in recs]))
                noauth_v.set(bool(cfg2.get("smtp", {}).get("no_auth", False)))
                sc2 = cfg2.get("schedule", {}) or {}
                mode_v.set(str(sc2.get("mode", "interval")))
                sm = sc2.get("every_minutes", 180)
                try:
                    sm = int(sm)
                except Exception:
                    pass
                every_v.set(f"{sm}m")
                time_v.set(str(sc2.get("time", "00:00")))
                try:
                    sdow = sc2.get("dow", []) or []
                    for code, var in dow_vars.items():
                        var.set(code in sdow)
                except Exception:
                    pass
                try:
                    sdom = sc2.get("dom", []) or []
                    dom_v.set(", ".join(str(x) for x in sdom))
                except Exception:
                    pass
                try:
                    refresh_sched_mode_ui()
                except Exception:
                    pass
                try:
                    _resize_to_fit()
                    root.after(0, _resize_to_fit)
                except Exception:
                    pass
            except Exception:
                pass
            messagebox.showinfo("HDDkeeper", "Imported settings.json")
        else:
            messagebox.showerror("HDDkeeper", f"Error: {r}")

    ttk.Button(frm_mail, text="Save SMTP", command=ui_save_smtp).grid(row=row, column=0, **pad)
    ttk.Button(frm_mail, text="Set password", command=ui_set_pwd).grid(row=row, column=1, **pad)
    ttk.Button(frm_mail, text="Test email", command=ui_test_email).grid(row=row, column=2, **pad)

    rowt = 0
    ttk.Label(frm_tasks, text="Mode").grid(row=rowt, column=0, **pad)
    cmb_mode = ttk.Combobox(frm_tasks, textvariable=mode_v, values=["interval", "calendar"], state="readonly")
    cmb_mode.grid(row=rowt, column=1, **pad)
    rowt += 1

    frm_interval = ttk.Frame(frm_tasks)
    frm_interval.grid(row=rowt, column=0, columnspan=3, sticky="we")
    ttk.Label(frm_interval, text="Every (e.g., 3h, 180m, 1d)").grid(row=0, column=0, **pad)
    ttk.Entry(frm_interval, textvariable=every_v).grid(row=0, column=1, **pad)
    ttk.Button(frm_interval, text="Set", command=ui_set_schedule).grid(row=0, column=2, **pad)

    frm_calendar = ttk.Frame(frm_tasks)
    frm_calendar.grid(row=rowt, column=0, columnspan=3, sticky="we")
    ttk.Label(frm_calendar, text="Time (HH:MM)").grid(row=0, column=0, **pad)
    ttk.Entry(frm_calendar, textvariable=time_v, width=8).grid(row=0, column=1, sticky="w", padx=6, pady=4)
    ttk.Label(frm_calendar, text="Days of week").grid(row=1, column=0, **pad)
    _dow_codes = ("MON","TUE","WED","THU","FRI","SAT","SUN")
    dow_frame = ttk.Frame(frm_calendar)
    dow_frame.grid(row=1, column=1, columnspan=3, sticky="w", padx=6, pady=2)
    for i, code in enumerate(_dow_codes):
        r = 0 if i < 4 else 1
        c = i if i < 4 else i - 4
        ttk.Checkbutton(dow_frame, text=code, variable=dow_vars[code]).grid(row=r, column=c, padx=6, pady=2, sticky="w")
    ttk.Label(frm_calendar, text="Days of month").grid(row=2, column=0, **pad)
    ttk.Entry(frm_calendar, textvariable=dom_v).grid(row=2, column=1, columnspan=2, **pad)
    ttk.Button(frm_calendar, text="Set", command=ui_set_schedule_calendar).grid(row=2, column=3, **pad)

    def _resize_to_fit():
        try:
            root.update_idletasks()
            w = root.winfo_reqwidth()
            h = root.winfo_reqheight()
            if w and h:
                root.geometry(f"{w}x{h}")
                try:
                    root.minsize(w, h)
                except Exception:
                    pass
        except Exception:
            pass

    def refresh_sched_mode_ui(*_):
        if mode_v.get() == "calendar":
            try:
                frm_interval.grid_remove()
            except Exception:
                pass
            try:
                frm_calendar.grid()
            except Exception:
                pass
        else:
            try:
                frm_calendar.grid_remove()
            except Exception:
                pass
            try:
                frm_interval.grid()
            except Exception:
                pass
        _resize_to_fit()

    cmb_mode.bind('<<ComboboxSelected>>', lambda e: refresh_sched_mode_ui())
    refresh_sched_mode_ui()
    rowt += 1
    ttk.Button(frm_tasks, text="Install tasks", command=ui_install).grid(row=rowt, column=0, **pad)
    ttk.Button(frm_tasks, text="Remove tasks", command=ui_uninstall).grid(row=rowt, column=1, **pad)
    def ui_start_tray():
        if _tray_is_running():
            messagebox.showinfo("HDDkeeper", "Tray is already running")
            return
        ok = _launch_tray()
        if not ok:
            messagebox.showerror("HDDkeeper", "Unable to start tray")
    ttk.Button(frm_tasks, text="Start tray", command=ui_start_tray).grid(row=rowt, column=2, **pad)

    ttk.Button(frm_export, text="Export settings", command=ui_export).grid(row=0, column=0, **pad)
    ttk.Button(frm_export, text="Export + password", command=ui_export_with_pwd).grid(row=0, column=1, **pad)
    ttk.Button(frm_export, text="Import settings", command=ui_import).grid(row=0, column=2, **pad)

    accept_btn = ttk.Button(frm_actions, text="Accept baseline", command=ui_accept)
    accept_btn.grid(row=0, column=0, padx=6, pady=6, sticky="we")
    ttk.Button(frm_actions, text="Scan now", command=ui_scan).grid(row=0, column=1, padx=6, pady=6, sticky="we")

    def _bind_clip_ops(w):
        m = tk.Menu(w, tearoff=0)
        m.add_command(label="Cut", command=lambda ww=w: ww.event_generate('<<Cut>>'))
        m.add_command(label="Copy", command=lambda ww=w: ww.event_generate('<<Copy>>'))
        m.add_command(label="Paste", command=lambda ww=w: ww.event_generate('<<Paste>>'))
        m.add_separator()
        m.add_command(label="Select All", command=lambda ww=w: ww.event_generate('<<SelectAll>>'))
        def popup(e, mm=m, ww=w):
            ww.focus_set()
            try:
                mm.tk_popup(e.x_root, e.y_root)
            finally:
                try:
                    mm.grab_release()
                except Exception:
                    pass
        w.bind('<Button-3>', popup, add='+')
        w.bind('<Control-v>', lambda e, ww=w: ww.event_generate('<<Paste>>'), add='+')
        w.bind('<Control-V>', lambda e, ww=w: ww.event_generate('<<Paste>>'), add='+')
        w.bind('<Shift-Insert>', lambda e, ww=w: ww.event_generate('<<Paste>>'), add='+')
        w.bind('<Control-c>', lambda e, ww=w: ww.event_generate('<<Copy>>'), add='+')
        w.bind('<Control-C>', lambda e, ww=w: ww.event_generate('<<Copy>>'), add='+')
        w.bind('<Control-Insert>', lambda e, ww=w: ww.event_generate('<<Copy>>'), add='+')
        w.bind('<Control-x>', lambda e, ww=w: ww.event_generate('<<Cut>>'), add='+')
        w.bind('<Control-X>', lambda e, ww=w: ww.event_generate('<<Cut>>'), add='+')
        w.bind('<Shift-Delete>', lambda e, ww=w: ww.event_generate('<<Cut>>'), add='+')
        w.bind('<Control-a>', lambda e, ww=w: ww.event_generate('<<SelectAll>>'), add='+')
        w.bind('<Control-A>', lambda e, ww=w: ww.event_generate('<<SelectAll>>'), add='+')
        def on_ctrl_key(e, ww=w):
            code = getattr(e, 'keycode', None)
            if code in (86,):
                ww.event_generate('<<Paste>>'); return 'break'
            if code in (67,):
                ww.event_generate('<<Copy>>'); return 'break'
            if code in (88,):
                ww.event_generate('<<Cut>>'); return 'break'
            if code in (65,):
                ww.event_generate('<<SelectAll>>'); return 'break'
        w.bind('<Control-KeyPress>', on_ctrl_key, add='+')

    def _attach_clipboard_bindings(container):
        for child in container.winfo_children():
            try:
                if isinstance(child, (tk.Entry, ttk.Entry, ttk.Combobox)):
                    _bind_clip_ops(child)
            except Exception:
                pass
            _attach_clipboard_bindings(child)

    _attach_clipboard_bindings(root)

    # Auto-size window to fit content
    try:
        root.update_idletasks()
        w = root.winfo_reqwidth()
        h = root.winfo_reqheight()
        if w and h:
            root.geometry(f"{w}x{h}")
            try:
                root.minsize(w, h)
            except Exception:
                pass
    except Exception:
        pass
    root.mainloop()
    return 0


def main():
    # If packaged with no args: HDDkeeperTray.exe -> tray, HDDkeeper.exe -> GUI
    try:
        if getattr(sys, "frozen", False) and len(sys.argv) == 1:
            exe_name = os.path.basename(sys.executable).lower()
            if "tray" in exe_name:
                return tray_main()
            else:
                return gui_main()
    except Exception:
        pass

    if not getattr(sys, "frozen", False) and len(sys.argv) == 1:
        return gui_main()

    ap = argparse.ArgumentParser(prog="hddkeeper", add_help=True)
    # Scan/Baseline
    ap.add_argument("--scan", action="store_true", help="Scan and print current disks")
    ap.add_argument("--accept-baseline", action="store_true", help="Scan and save as accepted baseline")
    ap.add_argument("--compare", action="store_true", help="Compare current disks with accepted baseline")
    ap.add_argument("--capture-candidate", action="store_true", help="Scan and save candidate baseline (not used for compare)")
    ap.add_argument("--show-baseline", action="store_true", help="Print accepted baseline if exists")
    ap.add_argument("--notify-if-diff", action="store_true", help="Compare and send email if disks changed")
    # Scheduler / Tray
    ap.add_argument("--set-schedule", dest="set_schedule", help="Set periodic scan interval, e.g. 3h, 180m, 1d")
    ap.add_argument("--set-schedule-at", action="store_true", help="Set calendar schedule at specific time")
    ap.add_argument("--time", dest="at_time", help="Time in HH:MM for calendar schedule")
    ap.add_argument("--dow", dest="dow", help="Days of week, CSV e.g. MON,WED or ПН,СР")
    ap.add_argument("--dom", dest="dom", help="Days of month, CSV of numbers e.g. 1,15,31")
    ap.add_argument("--init", action="store_true", help="Install Task Scheduler tasks (startup + periodic)")
    ap.add_argument("--install-tasks", action="store_true", help="Create/update scheduled tasks (alias of --init)")
    ap.add_argument("--run-now", action="store_true", help="Run scheduled task(s) immediately")
    ap.add_argument("--tray", action="store_true", help="Start Tray UI (pystray)")
    ap.add_argument("--gui", action="store_true", help="Start GUI window")
    # SMTP config
    ap.add_argument("--set-smtp", action="store_true", help="Set SMTP settings")
    ap.add_argument("--host", dest="host")
    ap.add_argument("--port", dest="port", type=int)
    ap.add_argument("--security", choices=["none", "starttls", "ssl"], help="SMTP security: none|starttls|ssl")
    ap.add_argument("--user", dest="user")
    ap.add_argument("--from-addr", dest="from_addr")
    ap.add_argument("--recipients", dest="recipients", help="Comma/semicolon separated emails, up to 10")
    ap.add_argument("--recipient", dest="recipient", action="append", help="Add one recipient (can be repeated)")
    ap.add_argument("--no-auth", action="store_true", help="Do not authenticate to SMTP (open relay or IP-auth)")
    ap.add_argument("--set-smtp-password", action="store_true", help="Set SMTP password securely")
    ap.add_argument("--test-email", action="store_true", help="Send a test email using current SMTP settings")
    ap.add_argument("--export-settings", action="store_true", help="Export portable settings.json next to EXE")
    ap.add_argument("--include-password", action="store_true", help="When exporting, include plaintext password")
    ap.add_argument("--import-settings", action="store_true", help="Import settings.json next to EXE into local config")
    ap.add_argument("--uninit", action="store_true", help="Remove Task Scheduler tasks")
    # Output
    ap.add_argument("--pretty", action="store_true", help="Pretty JSON output")
    args = ap.parse_args()

    # GUI / Tray UI
    if args.tray:
        code = tray_main()
        return code
    if args.gui:
        return gui_main()

    # Scheduler flows
    if args.set_schedule:
        cfg = set_schedule_config_every(args.set_schedule)
        _print_json({"status": "ok", "every_minutes": cfg.get("schedule", {}).get("every_minutes")}, args.pretty)
        return 0

    if getattr(args, "set_schedule_at", False):
        cfg = set_schedule_time_config(args.at_time or "00:00", args.dow or "", args.dom or "")
        _print_json({"status": "ok", "mode": cfg.get("schedule", {}).get("mode"), "time": cfg.get("schedule", {}).get("time"), "dow": cfg.get("schedule", {}).get("dow"), "dom": cfg.get("schedule", {}).get("dom")}, args.pretty)
        return 0

    if args.init or getattr(args, "install_tasks", False):
        res = install_tasks()
        res["status"] = "ok"
        _print_json(res, args.pretty)
        return 0

    if getattr(args, "run_now", False):
        res = run_now_tasks()
        _print_json(res, args.pretty)
        return 0

    if args.uninit:
        res = uninstall_tasks()
        _print_json(res, args.pretty)
        return 0

    # SMTP flows
    if args.set_smtp:
        # Combine recipients from --recipients and repeated --recipient
        recipients_csv = args.recipients
        if getattr(args, "recipient", None):
            if recipients_csv:
                recipients_csv = ";".join([recipients_csv] + args.recipient)
            else:
                recipients_csv = ";".join(args.recipient)
        cfg = set_smtp_config(args.host, args.port, args.security, args.user, args.from_addr, recipients_csv, args.no_auth)
        _print_json({"status": "ok", "smtp": cfg.get("smtp")}, args.pretty)
        return 0

    if args.set_smtp_password:
        try:
            set_smtp_password_interactive()
            _print_json({"status": "ok"}, args.pretty)
        except Exception as e:
            _print_json({"error": str(e)}, args.pretty)
        return 0

    if args.test_email:
        try:
            res = send_email_diff({}, is_test=True)
            _print_json(res, args.pretty)
        except Exception as e:
            _print_json({"error": str(e)}, args.pretty)
        return 0

    if args.export_settings:
        path = export_portable_settings(include_password=args.include_password)
        _print_json({"status": "ok", "path": path, "included_password": args.include_password}, args.pretty)
        return 0

    if args.import_settings:
        res = import_portable_settings(overwrite=True, include_password=False)
        _print_json(res, args.pretty)
        return 0

    if args.notify_if_diff:
        diff = notify_if_diff(args.pretty)
        _print_json(diff, args.pretty)
        return 0

    if args.accept_baseline:
        bl = accept_current_baseline()
        _print_json({"status": "ok", "baseline_accepted_at": bl.get("accepted_at"), "count": len(bl.get("disks", []))}, args.pretty)
        return 0

    if args.compare:
        diff = compare_with_baseline()
        _print_json(diff, args.pretty)
        return 0

    if args.capture_candidate:
        cand = capture_candidate_baseline()
        _print_json({"status": "ok", "candidate_captured_at": cand.get("captured_at"), "count": len(cand.get("disks", []))}, args.pretty)
        return 0

    if args.show_baseline:
        bl = load_json(baseline_path())
        if bl is None:
            _print_json({"error": "no_baseline"}, args.pretty)
        else:
            _print_json(bl, args.pretty)
        return 0

    if args.scan:
        data = scan_disks()
        _print_json(data, args.pretty)
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
