import os
from rq import Queue
from redis import Redis
import json
from typing import Dict, Any, List, Optional

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
redis_conn = Redis.from_url(REDIS_URL)
queue = Queue("vulnez", connection=redis_conn)

def enqueue_job(name: str, cmd: List[str], meta: Optional[Dict[str, Any]] = None):
    job = queue.enqueue('vulnez.task_worker.execute_cmd', args=(cmd,), kwargs={'meta': meta or {}}, result_ttl=86400)
    return job.get_id()

def enqueue_tasks_bulk(tasks: List[Dict[str, Any]]) -> int:
    count = 0
    for t in tasks:
        enqueue_job(t.get('name'), t.get('cmd', []), meta={'target': t.get('target','')})
        count += 1
    return count
