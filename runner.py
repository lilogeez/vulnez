# runner.py - safe subprocess runner
import shlex, subprocess, logging, time, os
from typing import List, Optional, Dict, Any
from shutil import which

log = logging.getLogger("vulnez.runner")
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

SENSITIVE_KEYS = ["-p", "--password", "-H", "--hash", "-u", "--user", "password", "hash", "--pass"]

def _mask_args(args: List[str]) -> List[str]:
    masked = []
    skip_next = False
    for a in args:
        if skip_next:
            masked.append("*****"); skip_next = False; continue
        lower = a.lower()
        if any(k == lower for k in SENSITIVE_KEYS):
            masked.append(a); skip_next = True
        elif any(a.startswith(k + "=") for k in SENSITIVE_KEYS):
            key, _, _ = a.partition("=")
            masked.append(f"{key}=*****")
        else:
            masked.append(a)
    return masked

def safe_split(command: str) -> List[str]:
    return shlex.split(command)

def safe_run(command: List[str], timeout: Optional[int] = None, cwd: Optional[str] = None,
             env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    masked = _mask_args(command)
    log.info("Executing: %s", " ".join(masked))
    try:
        start = time.time()
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout, cwd=cwd, env=env)
        duration = time.time() - start
        return {
            "command": command,
            "masked": masked,
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "duration": duration,
            "success": proc.returncode == 0
        }
    except subprocess.TimeoutExpired as e:
        log.warning("Timeout: %s", " ".join(masked))
        return {"command": command, "masked": masked, "returncode": None, "stdout": getattr(e,"stdout","") or "", "stderr": "timeout", "duration": timeout, "success": False, "error": "timeout"}
    except Exception as e:
        log.exception("Exception running: %s", " ".join(masked))
        return {"command": command, "masked": masked, "returncode": None, "stdout": "", "stderr": str(e), "duration": 0.0, "success": False, "error": "exception"}

def find_executable(name: str) -> Optional[str]:
    p = which(name)
    if p: return p
    local = os.path.expanduser(f"~/.local/bin/{name}")
    if os.path.isfile(local) and os.access(local, os.X_OK): return local
    return None
