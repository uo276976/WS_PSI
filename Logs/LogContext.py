import time, threading, os, psutil
from contextlib import contextmanager
from Logs.Logs import get_container_limits, log_activity_to_firebase, ThreadData
from Network.collections.DbConstants import VERSION


@contextmanager
def with_log_context(handler, cs, step_name, device=None):
    proc = psutil.Process(os.getpid())
    cpu_cores = get_container_limits().get("cpu_cores", psutil.cpu_count())

    try:
        proc.cpu_percent(None)
    except Exception:
        pass

    cpu_before = proc.cpu_times()
    mem_before = proc.memory_info().rss
    start_time = time.perf_counter()

    td = handler.thread_data if getattr(handler, "logging_active", False) else ThreadData()

    try:
        yield td
    finally:
        duration = time.perf_counter() - start_time
        cpu_after = proc.cpu_times()
        mem_after = proc.memory_info().rss

        user_cpu = cpu_after.user - cpu_before.user
        system_cpu = cpu_after.system - cpu_before.system
        total_cpu_time = user_cpu + system_cpu

        est_by_times = (total_cpu_time / max(duration, 1e-6) / max(cpu_cores, 1e-6)) * 100.0

        sample_interval = max(SAMPLING_INTERVAL, min(0.1, duration * 1.5))
        try:
            sampled = proc.cpu_percent(interval=sample_interval) / max(cpu_cores, 1e-6)
        except Exception:
            sampled = 0.0

        if duration < 0.05:
            cpu_percent_est = sampled
        else:
            cpu_percent_est = 0.5 * est_by_times + 0.5 * sampled

        cpu_percent_est = max(0.0, min(cpu_percent_est, 100.0))
        epsilon = 0.2
        if 0.0 < cpu_percent_est < epsilon:
            cpu_percent_est = epsilon
        if 100.0 - epsilon < cpu_percent_est < 100.0:
            cpu_percent_est = 100.0 - epsilon

        ram_usage_mb = round(proc.memory_info().rss / (1024**2), 2)

        if not getattr(handler, "logging_active", False) or not handler.thread_data:
            td.avg_instance_cpu_usage = round(cpu_percent_est, 2)
            td.avg_instance_ram_usage = ram_usage_mb
        else:
            td.avg_instance_cpu_usage = round(cpu_percent_est, 2)
            td.avg_instance_ram_usage = ram_usage_mb

        td_snapshot = type("TD", (), vars(td).copy())() if td is not None else ThreadData()
        peer_type = (
            handler.devices.get(device, {}).get("device_type", "Unknown")
            if hasattr(handler, "devices") and device in handler.devices else "Unknown"
        )

        threading.Thread(
            target=log_activity_to_firebase,
            args=(
                td_snapshot,
                f"INTERSECTION_{step_name}_{cs.imp_name}",
                round(duration, 6),
                VERSION,
                handler.id,
                getattr(handler, "device_type", "Unknown"),
                peer_type,
                cs.imp_name,
                getattr(cs, "category", "NIKE"),
                step_name,
                device,
            ),
            daemon=True,
        ).start()
