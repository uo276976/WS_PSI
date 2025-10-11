import time
from contextlib import contextmanager
from Logs import Logs
from Logs.Logs import ThreadData
from Network.collections.DbConstants import VERSION


@contextmanager
def with_log_context(handler, cs, step_name, device=None):
    """
    Context manager to automatically start/stop logging for a handler step.

    Parameters:
    - handler: self (the handler instance)
    - cs: crypto scheme helper (provides imp_name and category)
    - step_name: str (e.g., "FIRST_STEP", "SECOND_STEP", "FINAL_STEP")
    - device: optional device identifier
    """
    thread_data = ThreadData()
    Logs.start_logging(thread_data)
    start_time = time.time()

    try:
        yield thread_data  # yield control to the wrapped block
    finally:
        duration = time.time() - start_time
        Logs.stop_logging(thread_data)
        Logs.log_activity(
            thread_data,
            f"INTERSECTION_{step_name}_{cs.imp_name}",
            duration,
            VERSION,
            handler.id,
            device_type=getattr(handler, "device_type", "Unknown"),
            scheme=cs.imp_name,
            category=getattr(cs, "category", "NIKE"),
            step=step_name,
        )
