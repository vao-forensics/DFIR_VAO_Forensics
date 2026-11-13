"""Shared mutable state for background worker threads."""
import threading, time

# Mutable containers so cross-module assignment works
_state = {
    'last_user_request_ts': time.time(),
    'idle_worker_running': False,
}

_idle_worker_stop = threading.Event()
_qa_case_queue: list = []
_qa_queue_lock = threading.Lock()
_bg_llm_lock = threading.Semaphore(1)
