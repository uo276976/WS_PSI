import sys
import datetime, os, psutil, threading, time, platform, numpy as np
from firebase_admin import credentials, db, initialize_app
from Network.collections.DbConstants import FB_URL


SAMPLING_INTERVAL = 0.02
default_app = None


def connect_firebase():
    """
    Initialize Firebase if credentials are available.
    """
    global default_app
    if default_app is not None:
        return "Firebase already connected"
    try:
        cred = credentials.Certificate('./FirebaseCredentials.json')
        default_app = initialize_app(cred, {'databaseURL': FB_URL})
        print(f"[FIREBASE] Connected to Firebase project {default_app.project_id}")
        return f"Connected to Firebase project {default_app.project_id}"
    except Exception as e:
        print(f"[FIREBASE][WARN] Firebase not available: {e}")
        default_app = None
        return f"Firebase not available: {e}"

def disconnect_firebase():
    """
    Disconnect Firebase app.
    """
    global default_app
    if default_app is not None:
        from firebase_admin import delete_app
        delete_app(default_app)
        default_app = None
        print("[FIREBASE] Disconnected.")
        return "Firebase disconnected"
    return "Firebase was not connected"

connect_firebase()


class ThreadData:
    def __init__(self):
        self.cpu_usage, self.ram_usage = [], []
        self.instance_cpu_usage, self.instance_ram_usage = [], []
        self.timestamps = []
        self.avg_cpu_usage = self.avg_ram_usage = 0
        self.avg_instance_cpu_usage = self.avg_instance_ram_usage = 0
        self.peak_cpu_usage = self.peak_ram_usage = 0
        self.peak_instance_cpu_usage = self.peak_instance_ram_usage = 0
        self.stop_event = threading.Event()

def get_container_limits():
    if os.getenv("SINGLE_NODE_MODE", "false").lower() == "true":
        return {
            "cpu_cores": psutil.cpu_count(logical=True),
            "memory_mb": round(psutil.virtual_memory().total / (1024**2), 2)
        }
        
    cpu_cores = None
    mem_limit_bytes = psutil.virtual_memory().total
    
    try:
        if os.path.exists("/sys/fs/cgroup/cpu.max"):
            with open("/sys/fs/cgroup/cpu.max") as f:
                quota, period = f.read().strip().split()
                if quota != "max":
                    cpu_cores = float(quota) / float(period)
        elif os.path.exists("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"):
            with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") as f1, open("/sys/fs/cgroup/cpu/cpu.cfs_period_us") as f2:
                quota, period = int(f1.read()), int(f2.read())
                if quota > 0:
                    cpu_cores = float(quota) / float(period)
    except Exception as e:
        pass

    if cpu_cores is None or cpu_cores <= 0:
        cpu_cores = psutil.cpu_count(logical=False) or 1.0

    try:
        if os.path.exists("/sys/fs/cgroup/memory.max"):
            with open("/sys/fs/cgroup/memory.max") as f:
                val = f.read().strip()
                if val.isdigit():
                    mem_limit_bytes = int(val)
    except:
        pass

    cpu_env, mem_env = os.getenv("CPU_CORES"), os.getenv("MEMORY_MB")
    if cpu_env:
        cpu_cores = float(cpu_env)
    if mem_env:
        mem_limit_bytes = float(mem_env) * 1024 * 1024

    cpu_cores = max(cpu_cores, 0.05)
    return {
        "cpu_cores": round(cpu_cores, 3),
        "memory_mb": round(mem_limit_bytes / (1024**2), 2)
    }

def get_container_memory_usage():
    paths = ["/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.usage_in_bytes"]
    for p in paths:
        if os.path.exists(p):
            try:
                with open(p) as f:
                    return round(int(f.read().strip()) / (1024**2), 2)
            except:
                pass
    return round(psutil.virtual_memory().used / (1024**2), 2)

def log_cpu_usage(td: ThreadData):
    proc = psutil.Process(os.getpid())
    while not td.stop_event.is_set():
        td.cpu_usage.append(proc.cpu_percent(interval=None))
        time.sleep(SAMPLING_INTERVAL)

def log_instance_cpu_usage(td: ThreadData):
    proc = psutil.Process(os.getpid())
    cores = max(1e-3, get_container_limits()["cpu_cores"])

    try:
        proc.cpu_percent(None)
    except Exception:
        pass

    alpha = 0.3
    ema = 0.0

    while not td.stop_event.is_set():
        try:
            raw = proc.cpu_percent(interval=SAMPLING_INTERVAL)
            ema = (1 - alpha) * ema + alpha * raw

            # clamp a [0,100]
            if ema < 0.0: ema = 0.0
            if ema > 100.0: ema = 100.0

            td.instance_cpu_usage.append(round(ema, 2))
            td.timestamps.append(time.time())
        except Exception:
            td.instance_cpu_usage.append(0.0)
            td.timestamps.append(time.time())

            continue

def log_ram_usage(td: ThreadData):
    prev = None
    while not td.stop_event.is_set():
        try:
            current = get_container_memory_usage()

            if prev is not None:
                current = 0.7 * prev + 0.3 * current
            prev = current

            if current < 0:
                current = 0.0
            td.ram_usage.append(round(current, 2))
            td.timestamps.append(time.time())

        except Exception:
            td.ram_usage.append(0.0)

        time.sleep(SAMPLING_INTERVAL)


def log_instance_ram_usage(td: ThreadData):
    proc = psutil.Process(os.getpid())
    prev = None
    while not td.stop_event.is_set():
        try:
            rss_mb = round(proc.memory_info().rss / (1024 ** 2), 2)

            if prev is not None:
                rss_mb = 0.7 * prev + 0.3 * rss_mb
            prev = rss_mb

            if rss_mb < 0:
                rss_mb = 0.0

            td.instance_ram_usage.append(round(rss_mb, 2))

        except Exception:
            td.instance_ram_usage.append(0.0)

        time.sleep(SAMPLING_INTERVAL)

def start_logging(td: ThreadData):
    td.stop_event.clear()
    proc = psutil.Process(os.getpid())
    proc.cpu_percent(None)

    for fn in [log_cpu_usage, log_instance_cpu_usage, log_ram_usage, log_instance_ram_usage]:
        threading.Thread(target=fn, args=(td,), daemon=True).start()
    time.sleep(SAMPLING_INTERVAL * 2)

def stop_logging(td: ThreadData):
    td.stop_event.set()
    time.sleep(SAMPLING_INTERVAL * 6)
    _aggregate_stats(td)

def _aggregate_stats(td: ThreadData):
    def avg_peak_median(v):
        if not v:
            return 0.0, 0.0, 0.0
        vals = [x for x in v if 0 <= x < 1000]
        if not vals:
            return 0.0, 0.0, 0.0
        if len(vals) == 1:
            return vals[0], vals[0], vals[0]
        tail = vals[-max(3, len(vals)//5):]
        return round(np.mean(tail), 2), round(np.max(vals), 2), round(np.median(tail), 2)

    td.avg_cpu_usage, td.peak_cpu_usage, td.median_cpu_usage = avg_peak_median(td.cpu_usage)
    td.avg_instance_cpu_usage, td.peak_instance_cpu_usage, td.median_instance_cpu_usage = avg_peak_median(td.instance_cpu_usage)
    td.avg_ram_usage, td.peak_ram_usage, td.median_ram_usage = avg_peak_median(td.ram_usage)
    td.avg_instance_ram_usage, td.peak_instance_ram_usage, td.median_instance_ram_usage = avg_peak_median(td.instance_ram_usage)

def _push_log_async(ref, log):
    try:
        ref.push(log)
        activity = log.get("activity_code")
        log_id = log.get("id")

        if activity:
            print(f"[FIREBASE] Activity log pushed: {activity} ({log.get('device_type')}→{log.get('peer_device_type')})")
        elif "set_size" in log:
            print(f"[FIREBASE] Setup log pushed for {log_id}")
        elif "timestamps" in log:
            print(f"[FIREBASE] Temporal trace pushed for {log_id}")
        else:
            print(f"[FIREBASE] Generic log pushed for {log_id}")
    except Exception as e:
        print(f"[FIREBASE][ERROR] Failed to push log: {e}")
        
def push_temporal_trace(handler_id, td: ThreadData, scheme, step, device_type, max_points=10):
    """
    Push a compressed trace with at most 10 entries to Firebase.
    """
    if "pytest" in sys.modules or "unittest" in sys.modules:
        print(f"[TRACE][SKIPPED] push_temporal_trace skipped during tests for {handler_id}")
        return
    
    length = min(len(td.timestamps), len(td.instance_cpu_usage), len(td.instance_ram_usage))
    if length == 0:
        return

    if length > max_points:
        indices = np.linspace(0, length - 1, max_points, dtype=int)
    else:
        indices = range(length)

    data = {
        "id": handler_id,
        "timestamps": [td.timestamps[i] for i in indices],
        "cpu": [td.instance_cpu_usage[i] for i in indices],
        "ram": [td.instance_ram_usage[i] for i in indices],
        "scheme": scheme,
        "step": step,
        "device_type": device_type,
        "uploaded_at": datetime.datetime.now(datetime.UTC).isoformat() + "Z"
    }

    ref = db.reference(f"/logs/{handler_id.replace('.', '-')}/traces")
    threading.Thread(target=_push_log_async, args=(ref, data), daemon=True).start()


def log_activity_to_firebase(thread_data, activity_code, duration, version, handler_id,
                             device_type, peer_device_type, scheme, category, step, peer=None):
    if not default_app:
        print("[FIREBASE] Not connected.")
        return

    limits = get_container_limits()
    profile_mem = limits["memory_mb"]
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    
    if thread_data is None:
        print(f"[FIREBASE][WARN] Missing thread_data for {activity_code}, skipping metrics.")
        thread_data = type("EmptyTD", (), {
            "avg_instance_cpu_usage": 0.0,
            "avg_instance_ram_usage": 0.0,
            "peak_instance_cpu_usage": 0.0,
            "peak_instance_ram_usage": 0.0,
        })()

    log = {
        "id": handler_id,
        "timestamp": timestamp,
        "activity_code": activity_code,
        "time": round(duration, 6),
        "version": version,
        "device_type": device_type,
        "peer_device_type": peer_device_type,
        "scheme": scheme,
        "category": category,
        "step": step,
        "Avg_instance_CPU": f"{thread_data.avg_instance_cpu_usage}%",
        "Peak_instance_CPU": f"{thread_data.peak_instance_cpu_usage}%",
        "Avg_instance_RAM": f"{thread_data.avg_instance_ram_usage}MB / {profile_mem}MB",
        "Peak_instance_RAM": f"{thread_data.peak_instance_ram_usage}MB / {profile_mem}MB",
        "key_size_mb": getattr(thread_data, "key_size_mb", 0.0),
    }

    ref = db.reference(f"/logs/{handler_id.replace('.', '-')}/activities")
    threading.Thread(target=_push_log_async, args=(ref, log), daemon=True).start()

def get_logs(node_id: str):
    if not default_app:
        print("[FIREBASE] Not connected.")
        return {}
    ref = db.reference(f"/logs/{node_id.replace('.', '-')}/activities")
    data = ref.get()
    return data or {}

def setup_logs(node_id: str, set_size: int, domain: str, device_type="Unknown"):
    if not default_app:
        print("[FIREBASE] Not connected, skipping setup log.")
        return
    ref = db.reference(f"/logs/{node_id.replace('.', '-')}/setup")
    log = {
        "id": node_id,
        "timestamp": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "set_size": set_size,
        "domain": domain,
        "device_type": device_type,
        "Details": f"{platform.platform()} - {platform.machine()}",
    }
    threading.Thread(target=_push_log_async, args=(ref, log), daemon=True).start()

def aggregate_by_scheme():
    """
    Aggregate logs by cryptographic scheme, computing average
    time, CPU, RAM, and message/key sizes per scheme across all nodes and steps.
    """
    if not default_app:
        print("[FIREBASE] Not connected.")
        return []
    ref = db.reference("/logs")
    all_logs = ref.get()
    if not all_logs:
        return []

    from collections import defaultdict
    summary = defaultdict(list)

    for node_logs in all_logs.values():
        activities = node_logs.get("activities", {})
        for entry in activities.values():
            scheme = entry.get("scheme")
            if not scheme:
                continue
            try:
                cpu = float(entry.get("Avg_instance_CPU", "0").replace("%", ""))
                ram = float(entry.get("Avg_instance_RAM", "0").split("MB")[0])
                t = float(entry.get("time", 0))
                key_size = float(entry.get("key_size_mb", 0.0))
                device_type = entry.get("device_type", "Unknown")
                step = entry.get("step", "Unknown")
                summary[scheme].append({
                    "time": t,
                    "cpu": cpu,
                    "ram": ram,
                    "key_size": key_size,
                    "device_type": device_type,
                    "step": step
                })
            except Exception as e:
                print(f"[WARN] Skipping malformed entry for {scheme}: {e}")

    results = []
    for scheme, entries in summary.items():
        avg_time = sum(e["time"] for e in entries) / len(entries)
        avg_cpu = sum(e["cpu"] for e in entries) / len(entries)
        avg_ram = sum(e["ram"] for e in entries) / len(entries)
        avg_key = sum(e["key_size"] for e in entries) / len(entries)
        steps = sorted(set(e["step"] for e in entries))
        devices = sorted(set(e["device_type"] for e in entries))
        results.append({
            "scheme": scheme,
            "avg_time": round(avg_time, 3),
            "avg_cpu": round(avg_cpu, 2),
            "avg_ram": round(avg_ram, 2),
            "avg_key_size_mb": round(avg_key, 6),
            "steps": steps,
            "devices": devices,
            "count": len(entries)
        })

    return results
