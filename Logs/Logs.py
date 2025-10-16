import datetime
import os
import threading
import time
import numpy as np

import firebase_admin
import psutil
import platform

from firebase_admin import credentials, db

from Network.collections.DbConstants import FB_URL

global default_app
SAMPLING_INTERVAL = 0.05

def get_container_limits():
    """
    Detect CPU and memory limits enforced by Docker/Kubernetes (cgroups).
    Returns dict with 'cpu_cores' and 'memory_mb' fields.
    Falls back to host values if not limited.
    """
    cpu_quota = None
    cpu_period = None
    mem_limit = None

    # --- CPU limits ---
    cpu_paths = [
        "/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
        "/sys/fs/cgroup/cpu.max"
    ]
    for path in cpu_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    content = f.read().strip()
                    if " " in content:
                        quota_str, period_str = content.split()
                        if quota_str != "max":
                            cpu_quota = int(quota_str)
                            cpu_period = int(period_str)
                    else:
                        cpu_quota = int(content)
                        with open("/sys/fs/cgroup/cpu/cpu.cfs_period_us", "r") as f2:
                            cpu_period = int(f2.read().strip())
            except Exception:
                pass
            break

    # --- Memory limits ---
    for path in [
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        "/sys/fs/cgroup/memory.max"
    ]:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    val = f.read().strip()
                    if val.isdigit():
                        mem_limit = int(val)
                        break
            except Exception:
                pass

    # Compute effective CPU cores available to the container
    if cpu_quota and cpu_period and cpu_quota > 0:
        cpu_cores = cpu_quota / cpu_period
    else:
        cpu_cores = psutil.cpu_count()  # fall back to host count if unlimited

    # Compute effective memory in MB
    if mem_limit and mem_limit > 0 and mem_limit < psutil.virtual_memory().total:
        memory_mb = mem_limit / (1024 ** 2)
    else:
        memory_mb = psutil.virtual_memory().total / (1024 ** 2)

    return {
        "cpu_cores": round(cpu_cores, 2),
        "memory_mb": round(memory_mb, 2)
    }


def get_container_memory_usage():
    """
    Reads current container memory usage (in MB) using cgroup data.
    Falls back to psutil.virtual_memory().used if not in container.
    """
    paths = [
        "/sys/fs/cgroup/memory/memory.usage_in_bytes",
        "/sys/fs/cgroup/memory.current"
    ]
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    usage = int(f.read().strip())
                    return round(usage / (1024 ** 2), 2)
            except Exception:
                pass
    return round(psutil.virtual_memory().used / (1024 ** 2), 2)


# Detect limits once at startup
container_limits = get_container_limits()

DEVICE_PROFILES = {
    "WS": {
        "max_cpu_cores": min(4, container_limits["cpu_cores"]),
        "max_memory_mb": min(4096, container_limits["memory_mb"]),
        "description": "Workstation (high performance desktop/server)"
    },
    "Android": {
        "max_cpu_cores": min(2, container_limits["cpu_cores"]),
        "max_memory_mb": min(2048, container_limits["memory_mb"]),
        "description": "Mobile device (mid-range phone/tablet)"
    },
    "IoT": {
        "max_cpu_cores": min(1, container_limits["cpu_cores"]),
        "max_memory_mb": min(256, container_limits["memory_mb"]),
        "description": "Embedded/IoT board (Raspberry Pi / ESP32 class)"
    },
    "Unknown": {
        "max_cpu_cores": container_limits["cpu_cores"],
        "max_memory_mb": container_limits["memory_mb"],
        "description": "Default host capacity (detected)"
    }
}

def connect_firebase():
    global default_app
    if default_app is not None:
        return "Firebase was already connected"
    # Path to Firebase credentials, this file is not provided!!!
    try:
        cred = credentials.Certificate('./FirebaseCredentials.json')
        default_app = firebase_admin.initialize_app(cred, {
            'databaseURL': FB_URL
        })
        print(f"Connected to Firebase database: {default_app.project_id}")
        return f"Connected to Firebase database: {default_app.project_id}"
    except FileNotFoundError:
        default_app = None
        print("Firebase credentials not found, please provide the file in the root directory")
        print("The application will not log data to Firebase")
        return "Firebase credentials not found, please provide the file in the root directory"


def disconnect_firebase():
    global default_app
    if default_app is not None:
        firebase_admin.delete_app(default_app)
        default_app = None
        print("Disconnected from Firebase database - No logging to RTDB will be done")
        return "Disconnected from Firebase database - No logging to RTDB will be done"
    else:
        return "Firebase was not connected"


# noinspection PyRedeclaration
default_app = None
connect_firebase()


def firebase_connected(func):
    def wrapper(*args, **kwargs):
        if default_app is None:
            print("[FIREBASE] Not connected, skipping log.")
            return
        return func(*args, **kwargs)

    return wrapper


class ThreadData:
    def __init__(self):
        self.cpu_usage = []
        self.ram_usage = []
        self.instance_ram_usage = []
        self.instance_cpu_usage = []
        self.avg_cpu_usage = 0
        self.avg_ram_usage = 0
        self.avg_instance_ram_usage = 0
        self.avg_instance_cpu_usage = 0
        self.peak_cpu_usage = 0
        self.peak_ram_usage = 0
        self.peak_instance_ram_usage = 0
        self.peak_instance_cpu_usage = 0
        self.stop_event = threading.Event()


@firebase_connected
def log_activity(thread_data, activity_code, ttlog, version, id, peer=False,
                 my_data_size=None, ciphertext_size=None, scheme=None, category=None,
                 device_type=None, peer_device_type=None, step=None):

    profile = DEVICE_PROFILES.get(device_type, DEVICE_PROFILES["Unknown"])
    max_cores = profile["max_cpu_cores"]
    max_mem = profile["max_memory_mb"]

    relative_cpu_load = round(
        (thread_data.avg_instance_cpu_usage / (100 / profile["max_cpu_cores"])) * 100, 2
    )
    relative_ram_load = round(thread_data.avg_instance_ram_usage, 2)

    timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    log = {
        "id": id,
        "timestamp": timestamp,
        "version": version,
        "device_type": device_type,
        "peer_device_type": peer_device_type or "Unknown",
        "Details": f"{get_system_info()} - {profile['description']}",
        "activity_code": activity_code,
        "time": round(ttlog, 3),

        "Avg_RAM": get_ram_info(thread_data),
        "Peak_RAM": f"{thread_data.peak_ram_usage} MB",
        "Avg_instance_RAM": f"{thread_data.avg_instance_ram_usage} MB",
        "Peak_instance_RAM": f"{thread_data.peak_instance_ram_usage} MB",
        "Avg_CPU": f"{thread_data.avg_cpu_usage}% - {get_cpu_info()}",
        "Peak_CPU": f"{thread_data.peak_cpu_usage}%",
        "Avg_instance_CPU": f"{thread_data.avg_instance_cpu_usage}%",
        "Peak_instance_CPU": f"{thread_data.peak_instance_cpu_usage}%",
        "Relative_CPU_Load": f"{relative_cpu_load}%",
        "Relative_RAM_Load": f"{relative_ram_load}%",
        "Resource_Profile": profile["description"],
        "Max_CPU_Cores": max_cores,
        "Max_Memory_MB": max_mem,
    }

    if peer:
        log["peer"] = peer
    if my_data_size is not None:
        log["Cleartext_size"] = f"{my_data_size} bytes"
    if ciphertext_size is not None:
        log["Ciphertext_size"] = f"{ciphertext_size} bytes"
    if scheme:
        log["scheme"] = scheme
    if category:
        log["category"] = category
    if step:
        log["step"] = step

    ref = db.reference(f"/logs/{get_formatted_id(id)}/activities")

    try:
        ref.push(log)
        print(f"[FIREBASE] Activity log sent to Firebase for {activity_code} ({device_type} → {peer_device_type})")
    except Exception as e:
        print(f"[FIREBASE][ERROR] Failed to push log for {activity_code}: {e}")
        

def get_ram_info(thread_data):
    total_mem = container_limits["memory_mb"]
    mem_use_percent = round(thread_data.avg_ram_usage / total_mem * 100, 2)
    return f"{thread_data.avg_ram_usage} MB / {total_mem} MB - {mem_use_percent}%"


def get_cpu_info():
    limits = get_container_limits()
    cpu_freq = psutil.cpu_freq().current / 1000 if psutil.cpu_freq() else 0
    return f"{cpu_freq:.2f} GHz - limited to {limits['cpu_cores']} cores (container)"


def get_system_info():
    return f"{platform.platform()} - {platform.machine()}"


@firebase_connected
def get_logs(id):
    ref = db.reference(f"/logs/{get_formatted_id(id)}/activities")
    return ref.get()


def start_logging(thread_data):
    """Inicia los hilos de muestreo de CPU y RAM del sistema y del proceso actual."""
    pid = os.getpid()
    proc = psutil.Process(pid)

    proc.cpu_percent(interval=None)

    # First immediate samples
    thread_data.cpu_usage.append(psutil.cpu_percent(interval=0.05))
    thread_data.ram_usage.append(get_container_memory_usage())
    thread_data.instance_ram_usage.append(round(proc.memory_info().rss / (1024 ** 2), 2))
    thread_data.instance_cpu_usage.append(proc.cpu_percent(interval=0.05))

    threads = [
        threading.Thread(target=log_instance_ram_usage, args=(thread_data,), daemon=True),
        threading.Thread(target=log_instance_cpu_usage, args=(thread_data,), daemon=True),
        threading.Thread(target=log_cpu_usage, args=(thread_data,), daemon=True),
        threading.Thread(target=log_ram_usage, args=(thread_data,), daemon=True),
    ]

    thread_data.threads = threads
    
    for t in threads:
        t.start()


def stop_logging(thread_data):
    """Gracefully stop sampling threads and compute aggregated stats."""
    thread_data.stop_event.set()
    for t in getattr(thread_data, "threads", []):
        t.join(timeout=0.2)
    _aggregate_stats(thread_data)

def _aggregate_stats(thread_data):
    """Aggregate averages and peaks from recorded samples."""
    
    thread_data.avg_cpu_usage, thread_data.peak_cpu_usage = avg_and_peak(thread_data.cpu_usage)
    thread_data.avg_instance_cpu_usage, thread_data.peak_instance_cpu_usage = avg_and_peak(thread_data.instance_cpu_usage)
    thread_data.avg_ram_usage, thread_data.peak_ram_usage = avg_and_peak(thread_data.ram_usage)
    thread_data.avg_instance_ram_usage, thread_data.peak_instance_ram_usage = avg_and_peak(thread_data.instance_ram_usage)

def avg_and_peak(values):
    if not values:
        return 0.0, 0.0
    tail = values[-max(1, len(values)//5):]
    avg = np.mean(tail)
    return round(avg, 2), round(np.max(values), 2)

def stop_logging_cpu_usage(thread_data):
    if len(thread_data.cpu_usage) == 0:
        # fallback to a single psutil reading
        thread_data.cpu_usage = [psutil.cpu_percent(interval=0.1)]
    thread_data.avg_cpu_usage = round(sum(thread_data.cpu_usage) / len(thread_data.cpu_usage), 2)
    thread_data.peak_cpu_usage = round(max(thread_data.cpu_usage), 2)

    if len(thread_data.instance_cpu_usage) == 0:
        pid = os.getpid()
        proc = psutil.Process(pid)
        thread_data.instance_cpu_usage = [proc.cpu_percent(interval=0.1)]
    thread_data.avg_instance_cpu_usage = round(sum(thread_data.instance_cpu_usage) / len(thread_data.instance_cpu_usage), 2)
    thread_data.peak_instance_cpu_usage = round(max(thread_data.instance_cpu_usage), 2)


def stop_logging_ram_usage(thread_data):
    if len(thread_data.ram_usage) == 0:
        thread_data.ram_usage = [psutil.virtual_memory().used / (1024 ** 2)]
    thread_data.avg_ram_usage = round(sum(thread_data.ram_usage) / len(thread_data.ram_usage), 2)
    thread_data.peak_ram_usage = round(max(thread_data.ram_usage), 2)

    if len(thread_data.instance_ram_usage) == 0:
        pid = os.getpid()
        proc = psutil.Process(pid)
        thread_data.instance_ram_usage = [round(proc.memory_info().rss / (1024 ** 2), 2)]
    thread_data.avg_instance_ram_usage = round(sum(thread_data.instance_ram_usage) / len(thread_data.instance_ram_usage), 2)
    thread_data.peak_instance_ram_usage = round(max(thread_data.instance_ram_usage), 2)


def log_cpu_usage(thread_data):
    """System-wide CPU usage sampling."""
    while not thread_data.stop_event.is_set():
        value = psutil.cpu_percent(interval=None)
        thread_data.cpu_usage.append(value)
        time.sleep(SAMPLING_INTERVAL)
    return


def log_instance_cpu_usage(thread_data):
    """Per-process CPU usage sampling (scaled to container limit)."""
    pid = os.getpid()
    proc = psutil.Process(pid)
    limits = get_container_limits()
    container_cores = max(1e-3, limits.get("cpu_cores", psutil.cpu_count()))
    proc.cpu_percent(interval=None)
    while not thread_data.stop_event.is_set():
        raw_percent = proc.cpu_percent(interval=SAMPLING_INTERVAL)
        scaled = min(100.0, raw_percent / container_cores)
        thread_data.instance_cpu_usage.append(scaled)
    return


def log_ram_usage(thread_data):
    """System-wide RAM usage sampling."""
    while not thread_data.stop_event.is_set():
        used_mb = get_container_memory_usage()
        thread_data.ram_usage.append(round(used_mb, 2))
        time.sleep(SAMPLING_INTERVAL)
    return


def log_instance_ram_usage(thread_data):
    """Per-process RAM usage sampling."""
    pid = os.getpid()
    proc = psutil.Process(pid)
    while not thread_data.stop_event.is_set():
        rss = proc.memory_info().rss / (1024 ** 2)
        thread_data.instance_ram_usage.append(round(rss, 2))
        time.sleep(SAMPLING_INTERVAL)
    return


@firebase_connected
def setup_logs(id, set_size, domain):
    log = {
        "id": id,
        "timestamp": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "set_size": set_size,
        "domain": domain,
        "Details": "Desktop (Flask): " + get_system_info()
    }
    ref = db.reference(f"/logs/{get_formatted_id(id)}/setup")
    ref.push(log)
    print(f"Log setup sent to Firebase")


@firebase_connected
def log_result(implementation, result, version, id, device):
    timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    log = {
        "id": id,
        "timestamp": timestamp,
        "implementation": implementation,
        "result": result,
        "device": device,
        "version": version,
        "Details": "Desktop (Flask): " + get_system_info()
    }
    if isinstance(result, list):
        log["size"] = len(result)
    ref = db.reference(f"/logs/{get_formatted_id(id)}/results")
    ref.push(log)
    print(f"Result log sent to Firebase")
    return


def get_formatted_id(id):
    return id.replace(".", "-") if "[" not in id else id.replace("[", "").replace("]", "").replace(".", "-")

@firebase_connected
def aggregate_by_scheme():
    ref = db.reference(f"/logs")
    all_logs = ref.get()
    if not all_logs:
        return {}

    from collections import defaultdict
    summary = defaultdict(list)

    for node_logs in all_logs.values():
        activities = node_logs.get("activities", {})
        for entry in activities.values():
            scheme = entry.get("scheme")
            if not scheme:
                continue
            summary[scheme].append(entry)

    results = []
    for scheme, entries in summary.items():
        avg_time = sum(e["time"] for e in entries) / len(entries)
        avg_cpu = sum(float(e["Avg_CPU"].split('%')[0]) for e in entries if isinstance(e["Avg_CPU"], str) and "%" in e["Avg_CPU"]) / len(entries)
        avg_ram = sum(float(e["Avg_RAM"].split(' ')[0]) for e in entries if isinstance(e["Avg_RAM"], str)) / len(entries)

        results.append({
            "scheme": scheme,
            "category": entries[0].get("category", "Unknown"),
            "avg_time": round(avg_time, 3),
            "avg_cpu": round(avg_cpu, 2),
            "avg_ram": round(avg_ram, 2),
            "count": len(entries)
        })

    return results