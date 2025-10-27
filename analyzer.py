import hashlib
import os
import time
import magic

def analyze_file(filepath):
    # --- Calculate hashes ---
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
            md5.update(chunk)

    # --- Basic metadata ---
    size_bytes = os.path.getsize(filepath)
    size_kb = round(size_bytes / 1024, 2)
    size_mb = round(size_kb / 1024, 2)
    mime_type = magic.from_file(filepath, mime=True)
    extension = os.path.splitext(filepath)[1].lower().replace(".", "")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # --- Detection logic ---
    suspicious = []
    category = "Unknown"

    # ---- Category detection ----
    if "pdf" in mime_type:
        category = "Document / PDF"
    elif any(x in mime_type for x in ["image", "jpeg", "png", "gif"]):
        category = "Image"
    elif "text" in mime_type or extension in ["txt", "csv", "log"]:
        category = "Text File"
    elif "zip" in mime_type or "rar" in mime_type or extension in ["zip", "rar", "7z"]:
        category = "Archive / Compressed"
    elif "msword" in mime_type or extension in ["doc", "docx"]:
        category = "Microsoft Word Document"
    elif "excel" in mime_type or extension in ["xls", "xlsx"]:
        category = "Microsoft Excel Document"
    elif extension in ["docm", "xlsm", "pptm"]:
        category = "Office Document with Macros"
        suspicious.append("Macro-enabled Office file — potential script execution risk")
    elif extension in ["js", "vbs", "bat", "ps1", "cmd"]:
        category = "Script / Executable Script"
        suspicious.append("Script file detected — may contain executable code")
    elif "exe" in mime_type or "x-dosexec" in mime_type or extension in ["exe", "dll"]:
        category = "Executable"
        suspicious.append("Executable file detected — possible malware")
    elif extension in ["apk", "jar"]:
        category = "App Package / Java Archive"
        suspicious.append("Installable or Java-based executable file")

    # --- MIME vs Extension mismatch ---
    if extension not in mime_type:
        suspicious.append("Extension-MIME mismatch (file type does not match extension)")

    # --- Size heuristic for tiny executables ---
    if size_bytes < 20000 and category == "Executable":
        suspicious.append("Very small executable — possibly packed or obfuscated")

    # --- Final verdict ---
    if suspicious:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    # --- Return report dictionary ---
    return {
        "filename": os.path.basename(filepath),
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "size_bytes": size_bytes,
        "size_kb": size_kb,
        "size_mb": size_mb,
        "mime_type": mime_type,
        "timestamp": timestamp,
        "file_category": category,
        "verdict": verdict,
        "alerts": suspicious or ["No suspicious indicators detected"]
    }
import math
import re
from collections import Counter

def file_entropy(filepath, block_size=1024):
    """Calculate byte entropy (sampled) — higher entropy may indicate packing."""
    with open(filepath, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    freq = Counter(data)
    ln = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / ln
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_strings(filepath, min_len=4):
    """Extract ASCII strings from file as a safe, static artifact."""
    pattern = rb'[\x20-\x7E]{%d,}' % min_len
    results = []
    with open(filepath, "rb") as f:
        data = f.read()
        for match in re.findall(pattern, data):
            try:
                results.append(match.decode('utf-8', errors='ignore'))
            except:
                pass
    # return top few unique strings to keep payload small
    uniq = list(dict.fromkeys(results))
    return uniq[:50]

def simulate_dynamic_analysis(filepath):
    """
    Safe simulation of dynamic analysis:
    - compute file entropy
    - extract printable strings
    - search for suspicious keywords (powershell, cmd, createprocess, dllinject, rtf, macro, http)
    - produce a simulated timeline/log (non-executing)
    """
    entropy = file_entropy(filepath)
    strings = extract_strings(filepath)

    suspicious_keywords = [
        "powershell", "cmd.exe", "CreateRemoteThread", "VirtualAlloc", "LoadLibrary",
        "ShellExecute", "rundll32", "mshta", "wscript", "cscript", "schtasks", "regsvr32",
        "http://", "https://", "eval(", "base64", "exec(", "document.write", "macro"
    ]

    hits = []
    lower = " ".join(s.lower() for s in strings)
    for kw in suspicious_keywords:
        if kw.lower() in lower:
            hits.append(kw)

    simulated_timeline = [
        {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "event": "Simulated process started"},
        {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "event": "Scanned memory-like artifacts (simulation)"},
        {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "event": f"Found {len(hits)} suspicious keyword(s) in strings"},
    ]

    dynamic_log = {
        "entropy": entropy,
        "suspicious_string_hits": hits,
        "sample_strings": strings[:25],
        "simulated_timeline": simulated_timeline
    }
    return dynamic_log

