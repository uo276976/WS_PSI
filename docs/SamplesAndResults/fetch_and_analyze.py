import os
import json
import datetime
import firebase_admin
from firebase_admin import credentials, db
from Analyzer import analyze_activities

def connect_firebase():
    if not firebase_admin._apps:
        cred = credentials.Certificate('/home/alfonso/WS_PSI/FirebaseCredentials.json')
        firebase_admin.initialize_app(cred, {
            'databaseURL': "https://ws-psi-default-rtdb.europe-west1.firebasedatabase.app/"
        })

def fetch_all_logs():
    base_dir = "Experiments/FirebaseLogs"
    os.makedirs(base_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    ref = db.reference("/logs")
    all_logs = ref.get()
    if not all_logs:
        print("No logs found in Firebase.")
        return []

    files = []
    for node_id, node_data in all_logs.items():
        filename = f"{node_id}_{timestamp}.json"
        out_path = os.path.join(base_dir, filename)

        with open(out_path, "w") as f:
            json.dump(node_data, f, indent=2)

        files.append(out_path)
        print(f"Saved logs for {node_id} → {out_path}")
    return files

if __name__ == "__main__":
    connect_firebase()
    logs = fetch_all_logs()

    for log_file in logs:
        print(f"Analyzing {log_file}...")
        analyze_activities(os.path.basename(log_file), os.path.dirname(log_file) + "/")

