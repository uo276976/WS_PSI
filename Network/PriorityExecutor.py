import os
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from queue import PriorityQueue, Full, Empty

# Set up logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class PrioritizedItem:
    def __init__(self, priority, item):
        self.priority = priority
        self.item = item

    def __lt__(self, other):
        return self.priority < other.priority


class PriorityExecutor:
    def __init__(self, max_workers=None):
        # Benchmark Mode Setup
        benchmark_mode = os.getenv("BENCHMARK_MODE", "false").lower() == "true"
        self.benchmark_mode = benchmark_mode

        # Use 1 worker for benchmark mode, else default 2
        self.max_workers = 1 if benchmark_mode else (max_workers or 2)

        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.queue = PriorityQueue()
        self.max_tasks_in_queue = 3500
        self.tasks_in_progress = 0
        self._lock = threading.Lock()
        self._shutdown_flag = False
        self._start_thread()

        mode = "BENCHMARK" if benchmark_mode else "NORMAL"
        logger.info(f"[PriorityExecutor] Initialized in {mode} mode with {self.max_workers} workers")

    def _start_thread(self):
        def run():
            while not self._shutdown_flag:
                try:
                    prioritized_item = self.queue.get(timeout=0.1)
                    func, args, kwargs = prioritized_item.item
                    with self._lock:
                        self.tasks_in_progress += 1

                    future = self.executor.submit(func, *args, **kwargs)
                    future.add_done_callback(lambda _: self.task_done())
                    self.queue.task_done()

                except Empty:
                    continue
                except Exception as e:
                    logger.error(f"[PriorityExecutor] Error in run loop: {e}")
                    time.sleep(0.1)

        threading.Thread(target=run, daemon=True).start()

    def submit(self, priority, func, *args, **kwargs):
        try:
            item = PrioritizedItem(priority, (func, args, kwargs))
            self.queue.put_nowait(item)
            logger.debug(f"[PriorityExecutor] Task submitted: {func.__name__} (priority {priority})")
        except Full:
            logger.warning(f"[PriorityExecutor] Queue full - Task dropped: {func.__name__}")

    def task_done(self):
        with self._lock:
            self.tasks_in_progress -= 1
            logger.debug(f"[PriorityExecutor] Task completed. In progress: {self.tasks_in_progress}")

    def get_status(self):
        with self._lock:
            return {
                "in_queue": self.queue.qsize(),
                "in_progress": self.tasks_in_progress,
                "max_workers": self.max_workers,
                "max_tasks_in_queue": self.max_tasks_in_queue
            }

    def shutdown(self):
        self._shutdown_flag = True
        self.executor.shutdown(wait=True)
        logger.info("[PriorityExecutor] Shutdown complete")
