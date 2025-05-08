import datetime
import os
import threading
import time

import firebase_admin
import psutil
import platform

from firebase_admin import credentials, db

from Network.collections.DbConstants import FB_URL

global default_app
SAMPLING_INTERVAL = 0.1


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
                 my_data_size=None, ciphertext_size=None, scheme=None, category=None):
    timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    log = {
        "id": id,
        "timestamp": timestamp,
        "version": version,
        "Details": "Desktop (Flask): " + get_system_info(),
        "activity_code": activity_code,
        "time": round(ttlog, 3),
        "Avg_RAM": get_ram_info(thread_data),
        "Peak_RAM": str(thread_data.peak_ram_usage) + " MB",
        "Avg_instance_RAM": str(thread_data.avg_instance_ram_usage) + " MB",
        "Peak_instance_RAM": str(thread_data.peak_instance_ram_usage) + " MB",
        "Avg_CPU": str(thread_data.avg_cpu_usage) + "% - " + get_cpu_info() if thread_data.avg_cpu_usage else "N/A",
        "Peak_CPU": str(thread_data.peak_cpu_usage) + "%",
        "Avg_instance_CPU": str(thread_data.avg_instance_cpu_usage) + "%",
        "Peak_instance_CPU": str(thread_data.peak_instance_cpu_usage) + "%",
    }
    if peer:
        log["peer"] = peer
    if my_data_size is not None:
        log["Cleartext_size"] = str(my_data_size) + " bytes"
    if ciphertext_size is not None:
        log["Ciphertext_size"] = str(ciphertext_size) + " bytes"
    if scheme:
        log["scheme"] = scheme
    if category:
        log["category"] = category

    ref = db.reference(f"/logs/{get_formatted_id(id)}/activities")
    ref.push(log)

    print(f"Activity log sent to Firebase")


def get_ram_info(thread_data):
    mem_info = psutil.virtual_memory()
    total_mem = round(mem_info.total / (1024 ** 2), 2)
    mem_use_percent = round(thread_data.avg_ram_usage / total_mem * 100, 2)
    return f"{thread_data.avg_ram_usage} MB / {total_mem} MB - {mem_use_percent}%"


def get_cpu_info():
    cpu_info = psutil.cpu_freq().current / 1000, psutil.cpu_count()
    return f"{cpu_info[0]} GHz - {cpu_info[1]} cores"


def get_system_info():
    return f"{platform.platform()} - {platform.machine()}"


@firebase_connected
def get_logs(id):
    ref = db.reference(f"/logs/{get_formatted_id(id)}/activities")
    return ref.get()


def start_logging(thread_data):
    # Iniciar los hilos de registro
    threads = [threading.Thread(target=log_instance_ram_usage, args=(thread_data,)),
               threading.Thread(target=log_instance_cpu_usage, args=(thread_data,)),
               threading.Thread(target=log_cpu_usage, args=(thread_data,)),
               threading.Thread(target=log_ram_usage, args=(thread_data,))]
    for t in threads:
        t.start()


def stop_logging(thread_data):
    thread_data.stop_event.set()
    stop_logging_cpu_usage(thread_data)
    stop_logging_ram_usage(thread_data)


def stop_logging_cpu_usage(thread_data):
    result = sum(thread_data.cpu_usage) / len(thread_data.cpu_usage) if len(thread_data.cpu_usage) != 0 else 0
    thread_data.avg_cpu_usage = round(result, 2) if len(thread_data.cpu_usage) != 0 else 0
    thread_data.peak_cpu_usage = round(max(thread_data.cpu_usage), 2) if len(thread_data.cpu_usage) != 0 else 0
    # If len(instance_cpu_usage) == 0, the result will be Na
    if len(thread_data.instance_cpu_usage) == 0:
        thread_data.avg_instance_cpu_usage = 0
        thread_data.peak_instance_cpu_usage = 0
        return
    result = sum(thread_data.instance_cpu_usage) / len(thread_data.instance_cpu_usage)
    thread_data.avg_instance_cpu_usage = round(result, 2)
    thread_data.peak_instance_cpu_usage = round(max(thread_data.instance_cpu_usage), 2)
    return


def stop_logging_ram_usage(thread_data):
    if len(thread_data.ram_usage) == 0:
        thread_data.avg_ram_usage = 0
        thread_data.peak_ram_usage = 0
        thread_data.avg_instance_ram_usage = 0
        thread_data.peak_instance_ram_usage = 0
        return
    result = sum(thread_data.ram_usage) / len(thread_data.ram_usage)
    thread_data.avg_ram_usage = round(result, 2)
    thread_data.peak_ram_usage = round(max(thread_data.ram_usage), 2)
    result = sum(thread_data.instance_ram_usage) / len(thread_data.instance_ram_usage)
    thread_data.avg_instance_ram_usage = round(result, 2)
    thread_data.peak_instance_ram_usage = round(max(thread_data.instance_ram_usage), 2)
    return


def log_cpu_usage(thread_data):
    while not thread_data.stop_event.is_set():
        thread_data.cpu_usage.append(psutil.cpu_percent(interval=SAMPLING_INTERVAL))
    return


def log_ram_usage(thread_data):
    while not thread_data.stop_event.is_set():
        thread_data.ram_usage.append(psutil.virtual_memory().used / (1024 ** 2))
        time.sleep(0.05)
    return


def log_instance_ram_usage(thread_data):
    pid = os.getpid()
    python_process = psutil.Process(pid)
    while not thread_data.stop_event.is_set():
        memory_info = round(python_process.memory_info().rss / (1024 ** 2), 2)
        thread_data.instance_ram_usage.append(memory_info)
        time.sleep(0.05)
    return


def log_instance_cpu_usage(thread_data):
    pid = os.getpid()
    python_process = psutil.Process(pid)
    while not thread_data.stop_event.is_set():
        percent = python_process.cpu_percent(interval=SAMPLING_INTERVAL)
        thread_data.instance_cpu_usage.append(percent)
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