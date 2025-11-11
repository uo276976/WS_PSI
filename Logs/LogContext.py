import time, threading, os, psutil
from contextlib import contextmanager
from Logs.Logs import (
    get_container_limits, log_activity_to_firebase, ThreadData, SAMPLING_INTERVAL,
    start_logging, stop_logging, _aggregate_stats, push_temporal_trace
)
from Network.collections.DbConstants import VERSION


@contextmanager
def with_log_context(handler, cs, step_name, device=None):
    proc = psutil.Process(os.getpid())
    cpu_cores = get_container_limits().get("cpu_cores", psutil.cpu_count())

    try:
        proc.cpu_percent(None)  # warm-up
    except Exception:
        pass

    cpu_before = proc.cpu_times()
    start_time = time.perf_counter()

    ephemeral = not getattr(handler, "logging_active", False)
    td = handler.thread_data if not ephemeral else ThreadData()
    if ephemeral:
        start_logging(td)

    try:
        yield td
    finally:
        duration = time.perf_counter() - start_time
        cpu_after = proc.cpu_times()

        user_cpu = cpu_after.user - cpu_before.user
        system_cpu = cpu_after.system - cpu_before.system
        total_cpu_time = user_cpu + system_cpu

        limits = get_container_limits()
        cpu_quota = max(limits.get("cpu_cores", 1.0), 1e-6)
        host_cores = max(psutil.cpu_count(logical=True), 1)

        est_by_times = (total_cpu_time / max(duration, 1e-6)) / host_cores * 100.0

        try:
            raw_percent = proc.cpu_percent(interval=None)
        except Exception:
            raw_percent = 0.0

        sampled = raw_percent

        cpu_percent_est = 0.5 * est_by_times + 0.5 * sampled
        cpu_percent_est = max(0.0, min(cpu_percent_est, 100.0))
        epsilon = 0.2

        if 0.0 < cpu_percent_est < epsilon:
            cpu_percent_est = epsilon

        ram_usage_mb = round(proc.memory_info().rss / (1024**2), 2)

        cpu_within_quota = round(cpu_percent_est, 2)
        cpu_percent_est = cpu_within_quota

        if ephemeral:
            if not td.instance_cpu_usage and not td.instance_ram_usage:
                try:
                    _ = proc.cpu_percent(interval=SAMPLING_INTERVAL)
                except Exception:
                    pass
                td.instance_cpu_usage.append(cpu_percent_est)
                td.instance_ram_usage.append(ram_usage_mb)
                td.timestamps.append(time.time())

            stop_logging(td)
        else:
            _aggregate_stats(td)

        td.avg_instance_cpu_usage = round(
            0.7 * getattr(td, "avg_instance_cpu_usage", 0.0) + 0.3 * cpu_percent_est, 2
        )
        td.avg_instance_ram_usage = round(
            0.7 * getattr(td, "avg_instance_ram_usage", 0.0) + 0.3 * ram_usage_mb, 2
        )

        td_snapshot = type("TD", (), vars(td).copy())()

        peer_type = (
            handler.devices.get(device, {}).get("device_type", "Unknown")
            if hasattr(handler, "devices") and device in handler.devices else "Unknown"
        )
        scheme_name = getattr(cs, "imp_name", "Unknown")
        category = getattr(cs, "category", None)
        if not category or category == "Unknown":
            name_upper = scheme_name.upper()
            if "OPE" in name_upper and "CA" in name_upper: category = "PSI-CA"
            elif "OPE" in name_upper: category = "OPE"
            elif "DOMAIN" in name_upper: category = "PSI-Domain"
            elif "PSI" in name_upper: category = "PSI"
            else: category = "NIKE"

        td_snapshot.key_size_mb = getattr(handler, "_last_key_size_mb", 0.0)
        
        push_temporal_trace(
            handler.id,
            td_snapshot,
            scheme_name,
            step_name,
            getattr(handler, "device_type", "Unknown")
        )

        threading.Thread(
            target=log_activity_to_firebase,
            args=(
                td_snapshot,
                f"INTERSECTION_{step_name}_{scheme_name}",
                round(duration, 6),
                VERSION,
                handler.id,
                getattr(handler, "device_type", "Unknown"),
                peer_type,
                scheme_name,
                category,
                step_name,
                device,
            ),
            daemon=True,
        ).start()
