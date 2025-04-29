import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from queue import PriorityQueue, Full

# Set up logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Prioritized task wrapper
class PrioritizedItem:
    def __init__(self, priority, item):
        self.priority = priority
        self.item = item

    def __lt__(self, other):
        return self.priority > other.priority  # Higher priority first


class PriorityExecutor:
    def __init__(self, max_workers):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.queue = PriorityQueue()
        self.max_tasks_in_queue = 100
        self.tasks_in_progress = 0
        self._lock = threading.Lock()
        self._shutdown_flag = False
        self._start_thread()

    def _start_thread(self):
        def run():
            while not self._shutdown_flag:
                try:
                    if not self.queue.empty():
                        with self._lock:
                            if self.tasks_in_progress >= self.max_workers + self.max_tasks_in_queue:
                                time.sleep(0.1)
                                continue

                        prioritized_item = self.queue.get()
                        if prioritized_item:
                            func, args, kwargs = prioritized_item.item
                            future = self.executor.submit(func, *args, **kwargs)
                            with self._lock:
                                self.tasks_in_progress += 1
                            future.add_done_callback(lambda _: self.task_done())
                            self.queue.task_done()
                    else:
                        time.sleep(0.1)

                except Exception as e:
                    logger.error(f"[PriorityExecutor] Error in run loop: {e}")

        threading.Thread(target=run, daemon=True).start()

    def submit(self, priority, func, *args, **kwargs):
        try:
            if self.queue.qsize() < self.max_tasks_in_queue:
                self.queue.put_nowait(PrioritizedItem(priority, (func, args, kwargs)))
                logger.debug(f"[PriorityExecutor] Task submitted: {func.__name__} (priority {priority})")
            else:
                logger.warning(f"[PriorityExecutor] Task dropped (queue full): {func.__name__}")
        except Full:
            logger.warning(f"[PriorityExecutor] Queue full, could not submit task: {func.__name__}")

    def task_done(self):
        with self._lock:
            self.tasks_in_progress -= 1
            logger.debug(f"[PriorityExecutor] Task finished. In progress: {self.tasks_in_progress}")

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
