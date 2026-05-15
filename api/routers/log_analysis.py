import re
from pathlib import Path
from typing import List, Dict, Any

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import PlainTextResponse

router = APIRouter()

# ---------------------------------------------------------------------------
# Threat detection patterns
# Each entry: list of regex patterns, display label, severity, and minimum
# number of matches required to declare the threat present.
# ---------------------------------------------------------------------------
THREAT_PATTERNS: Dict[str, Dict[str, Any]] = {
    "brute_force": {
        "patterns": [
            r"(?i)Failed password for .+ from [\d.]+",
            r"(?i)authentication failure.*(ssh|login|ftp)",
            r"(?i)(Invalid|failed)\s+(login|password|authentication).+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"\b(401|403)\b.*(login|auth|signin)",
            r"(?i)too many (authentication|login) (attempts|failures)",
            r"(?i)account (locked|disabled) after .*(failed|invalid)",
            r"(?i)repeated (login|auth) failure",
        ],
        "label": "Brute Force Attack",
        "severity": "high",
        "threshold": 3,
    },
    "sql_injection": {
        "patterns": [
            r"(?i)(SELECT|UNION\s+SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE)",
            r"(?i)(%27|'|--|;)\s*(OR|AND)\s+[\w\s'\"=]+",
            r"(?i)(EXEC|EXECUTE|xp_cmdshell|sp_executesql)",
            r"(?i)(INFORMATION_SCHEMA|sys\.tables|all_tables|sqlite_master)",
            r"(?i)(1\s*=\s*1|1%3D1|'\s*=\s*'|or\s+1\s*=\s*1)",
            r"(?i)(SLEEP\s*\(\s*\d+|BENCHMARK\s*\(|WAITFOR\s+DELAY)",
            r"(?i)(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)",
            r"(?i)(CHAR\s*\(\s*\d+|CONCAT\s*\(|GROUP_CONCAT)",
        ],
        "label": "SQL Injection",
        "severity": "critical",
        "threshold": 1,
    },
    "malware": {
        "patterns": [
            r"(?i)(wget|curl)\s+http.+\.(exe|sh|bat|ps1|dll|vbs|py|msi)\b",
            r"(?i)(cmd\.exe|powershell(\.exe)?|wscript|cscript)\s.+(-enc|-encodedcommand|/c\s+|bypass)",
            r"(?i)(base64_decode|eval\s*\(\s*base64|atob\s*\()",
            r"(?i)\b(trojan|ransomware|keylogger|rootkit|spyware|adware|worm\.exe)\b",
            r"(?i)\b(nc|ncat|netcat)\s+(-[elp]+\s+)?\d{2,5}\b",
            r"(?i)(reverse_tcp|meterpreter|metasploit|shellcode|exploit)",
            r"(?i)(EICAR|malicious_file|virus_detected|quarantined)",
            r"(?i)C2\s*(server|callback|beacon|checkin)",
        ],
        "label": "Malware Activity",
        "severity": "critical",
        "threshold": 1,
    },
    "unauthorized_access": {
        "patterns": [
            r"(?i)\b(403|401)\b.+(/admin|/config|/etc/passwd|/root|/wp-admin|/phpmyadmin|/shell|/.env|/secrets)",
            r"(?i)(directory traversal|path traversal)",
            r"(\.\./){2,}",
            r"(?i)(/etc/passwd|/etc/shadow|/proc/self|/var/log/auth)",
            r"(?i)(unauthorized access|permission denied|access forbidden|access denied)",
            r"(?i)(privilege escalation|sudo\s+-u\s+root|su\s+root)",
            r"(?i)(invalid (token|session|cookie)|session (hijack|fixation|expired))",
            r"(?i)(forbidden|not allowed).+(resource|endpoint|path)",
        ],
        "label": "Unauthorized Access",
        "severity": "high",
        "threshold": 1,
    },
    "data_exfiltration": {
        "patterns": [
            r"(?i)(data.?exfil|exfiltrat)",
            r"(?i)(bytes_sent|data_out|outbound_bytes)\s*[=:]\s*[5-9]\d{5,}",
            r"(?i)(POST|PUT)\s+\S+\s+HTTP/\d\.\d\s+\d{3}\s+[5-9]\d{5,}",
            r"(?i)(dns.?tunnel|dns_query.+\.(tk|ml|ga|cf|gq)\b)",
            r"(?i)(large.?transfer|unusual.?(data|upload|outbound))",
            r"(?i)(uploaded?|transferr?ed?)\s+[5-9]\d{5,}\s*(bytes|kb|mb|gb)",
            r"(?i)(sensitive.?data.?(sent|transmitted|leaked)|data.?leak)",
            r"(?i)(egress|outbound).+(block|alert|detected)",
        ],
        "label": "Data Exfiltration",
        "severity": "critical",
        "threshold": 1,
    },
}

SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _compute_threat_score(threats: List[Dict]) -> int:
    """0–100 score based on detected threats and their severities."""
    if not threats:
        return 0
    base = min(len(threats) * 20, 60)
    max_sev = max(SEVERITY_ORDER.get(t["severity"], 0) for t in threats)
    sev_bonus = max_sev * 13
    return min(base + sev_bonus, 100)


def _status(score: int) -> str:
    if score == 0:
        return "clean"
    if score < 40:
        return "suspicious"
    return "malicious"


def analyze_log_content(content: str, filename: str) -> Dict[str, Any]:
    lines = content.splitlines()
    total_lines = len(lines)

    detected_threats: List[Dict] = []

    for threat_key, cfg in THREAT_PATTERNS.items():
        compiled = [re.compile(p) for p in cfg["patterns"]]
        matches = []
        seen_lines: set = set()

        for lineno, line in enumerate(lines, start=1):
            for pat in compiled:
                if pat.search(line) and lineno not in seen_lines:
                    seen_lines.add(lineno)
                    matches.append({"line_number": lineno, "content": line.strip()})
                    break  # one match per line per threat type

        if len(matches) >= cfg["threshold"]:
            detected_threats.append(
                {
                    "type": threat_key,
                    "label": cfg["label"],
                    "severity": cfg["severity"],
                    "match_count": len(matches),
                    "matched_lines": matches[:20],  # cap preview to 20 lines
                }
            )

    # Sort by severity desc then match count desc
    detected_threats.sort(
        key=lambda t: (SEVERITY_ORDER.get(t["severity"], 0), t["match_count"]),
        reverse=True,
    )

    score = _compute_threat_score(detected_threats)
    status = _status(score)

    if detected_threats:
        labels = ", ".join(t["label"] for t in detected_threats)
        summary = f"{len(detected_threats)} threat type(s) detected: {labels}"
    else:
        summary = "No threats detected — log appears clean"

    return {
        "filename": filename,
        "total_lines": total_lines,
        "status": status,
        "threat_score": score,
        "threats_detected": detected_threats,
        "summary": summary,
    }


SAMPLE_DIR = Path(__file__).parent.parent.parent / "data" / "sample_logs"

ALLOWED_SAMPLES = {
    "normal_access.log",
    "brute_force.log",
    "sql_injection.log",
    "malware_activity.log",
    "unauthorized_access.log",
    "data_exfiltration.log",
    "mixed_threats.log",
}


@router.get("/sample/{filename}", response_class=PlainTextResponse)
def get_sample(filename: str):
    if filename not in ALLOWED_SAMPLES:
        raise HTTPException(status_code=404, detail="Sample not found.")
    path = SAMPLE_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Sample file missing on server.")
    return path.read_text(encoding="utf-8")


@router.post("/analyze")
async def analyze_log(file: UploadFile = File(...)):
    if file.content_type and not file.content_type.startswith("text/"):
        # Accept common log mime types
        allowed = {"text/plain", "text/csv", "application/octet-stream", ""}
        if file.content_type not in allowed:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type '{file.content_type}'. Upload a plain-text log file.",
            )

    raw = await file.read()
    try:
        content = raw.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as UTF-8.")

    if not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    return analyze_log_content(content, file.filename or "uploaded.log")
