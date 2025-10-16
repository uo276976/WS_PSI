import os
import psutil
import time
import traceback
from contextlib import contextmanager
from Logs import Logs
from Logs.Logs import log_activity, start_logging, stop_logging, ThreadData, get_container_limits
from Network.collections.DbConstants import VERSION


@contextmanager
def with_log_context(handler, cs, step_name, device=None):
    """
    Context manager to automatically start/stop logging for a handler step.
    Collects accurate per-container CPU/memory metrics using cgroup limits.
    """
    print(f"[DEBUG] Entered with_log_context for {cs.imp_name} step={step_name} device={device}", flush=True)

    pid = os.getpid()
    proc = psutil.Process(pid)
    proc.cpu_percent(interval=None)  # reset CPU counters

    # Capture baseline stats
    start_time = time.perf_counter()
    start_mem = proc.memory_info().rss

    thread_data = ThreadData()
    start_logging(thread_data)

    try:
        yield thread_data
    finally:
        try:
            stop_logging(thread_data)

            end_time = time.perf_counter()
            duration = end_time - start_time
            end_mem = proc.memory_info().rss
            mem_delta_mb = (end_mem - start_mem) / (1024 ** 2)

            limits = get_container_limits()
            container_cores = limits.get("cpu_cores", psutil.cpu_count())

            # Use psutil's native percentage measurement, averaged over duration
            cpu_percent_est = proc.cpu_percent(interval=None) / container_cores
            cpu_percent_est = min(cpu_percent_est, 100.0)  # cap to 100%

            thread_data.avg_instance_cpu_usage = round(cpu_percent_est, 2)
            thread_data.peak_instance_cpu_usage = max(
                thread_data.peak_instance_cpu_usage,
                thread_data.avg_instance_cpu_usage,
            )
            thread_data.avg_instance_ram_usage += round(mem_delta_mb, 2)

            # Identify peer device type
            peer_type = "Unknown"
            if hasattr(handler, "devices") and device in handler.devices:
                peer_type = handler.devices[device].get("device_type", "Unknown")

            # Log
            log_activity(
                thread_data,
                f"INTERSECTION_{step_name}_{cs.imp_name}",
                duration,
                VERSION,
                handler.id,
                peer=device,
                device_type=getattr(handler, "device_type", None) or "Unknown",
                peer_device_type=peer_type,
                scheme=cs.imp_name,
                category=getattr(cs, "category", "NIKE"),
                step=step_name,
            )

            print(f"[DEBUG] Logged activity for {handler.id} ({handler.device_type})", flush=True)

        except Exception as e:
            print(f"[FATAL] Exception during log_context cleanup: {e}", flush=True)
            traceback.print_exc()
