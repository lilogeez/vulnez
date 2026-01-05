import asyncio
import json
import shlex
import os
import shutil
import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any
from vulnez.logger import logger

@dataclass
class Task:
    name: str
    cmd: List[str]
    env: Dict[str, str] = None
    timeout: int = 600
    destructive: bool = False

class TaskRunner:
    def __init__(self, concurrency:int=4, target:str='default', output_dir:Path=Path('outputs'), dry_run:bool=False, confirm_legal_plus:bool=False):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results:List[Dict[str,Any]] = []
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.target = target
        self.dry_run = dry_run
        self.confirm_legal_plus = confirm_legal_plus

    def _binary_exists(self, cmd:List[str]) -> bool:
        if not cmd: return False
        exe = cmd[0]
        if os.path.sep in exe:
            return Path(exe).exists()
        return shutil.which(exe) is not None

    async def _run_task(self, task:Task):
        async with self.semaphore:
            ts = datetime.datetime.datetime.utcnow().isoformat() + 'Z'
            cmd_line = ' '.join(shlex.quote(c) for c in task.cmd)
            logger.info("[%s] Menjalankan: %s -> %s", self.target, task.name, cmd_line)

            if task.destructive and not self.confirm_legal_plus:
                errmsg = f"Task '{task.name}' bersifat DESTRUCTIVE dan memerlukan --confirm-legal-plus."
                res = {"name":task.name,"cmd":task.cmd,"stderr":errmsg,"skipped":True,"ts":ts}
                self.results.append(res)
                (self.output_dir / f"{task.name.replace(' ','_')}.json").write_text(json.dumps(res, indent=2))
                return

            if not self._binary_exists(task.cmd):
                errmsg = f"Binary tidak ditemukan untuk task '{task.name}': {task.cmd[0]}"
                res = {"name":task.name,"cmd":task.cmd,"stderr":errmsg,"skipped":True,"ts":ts}
                self.results.append(res)
                (self.output_dir / f"{task.name.replace(' ','_')}.json").write_text(json.dumps(res, indent=2))
                logger.warning(errmsg)
                return

            if self.dry_run:
                res = {"name":task.name,"cmd":task.cmd,"stdout":"","stderr":"dry-run","skipped":True,"ts":ts}
                self.results.append(res)
                (self.output_dir / f"{task.name.replace(' ','_')}.json").write_text(json.dumps(res, indent=2))
                logger.info("Dry-run: %s", task.name)
                return

            env = os.environ.copy()
            if task.env: env.update(task.env)
            try:
                proc = await asyncio.create_subprocess_exec(*task.cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
                out, err = await asyncio.wait_for(proc.communicate(), timeout=task.timeout)
                returncode = proc.returncode
            except asyncio.TimeoutError:
                proc.kill()
                out, err = b"", b"Timed out"
                returncode = None
            except FileNotFoundError as e:
                out, err = b"", str(e).encode()
                returncode = None

            res = {
                "name": task.name,
                "cmd": task.cmd,
                "returncode": returncode,
                "stdout": (out.decode(errors='ignore') if isinstance(out,(bytes,bytearray)) else str(out)),
                "stderr": (err.decode(errors='ignore') if isinstance(err,(bytes,bytearray)) else str(err)),
                "ts": ts
            }
            self.results.append(res)
            safe = task.name.replace(' ','_').replace('/','_')
            p = self.output_dir / f"{safe}.json"
            try:
                p.write_text(json.dumps(res, indent=2))
            except Exception as e:
                logger.error("Gagal menyimpan hasil %s: %s", p, e)
            logger.info("Selesai: %s (rc=%s)", task.name, returncode)

    def run_tasks(self, tasks:List[Task]):
        asyncio.run(self._run_all(tasks))

    async def _run_all(self, tasks:List[Task]):
        await asyncio.gather(*(self._run_task(t) for t in tasks))
        summary_path = self.output_dir / 'summary.json'
        try:
            summary_path.write_text(json.dumps(self.results, indent=2))
            logger.info("Summary tersimpan: %s", summary_path)
        except Exception as e:
            logger.error("Gagal menulis summary: %s", e)
