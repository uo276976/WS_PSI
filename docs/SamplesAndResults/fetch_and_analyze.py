import os
import json
import datetime
import firebase_admin
from firebase_admin import credentials, db
from Analyzer import analyze_dir

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
        print("[Firebase] No se encontraron logs.")
        return base_dir, []

    files = []
    for node_id, node_data in all_logs.items():
        filename = f"{node_id}_{timestamp}.json"
        out_path = os.path.join(base_dir, filename)

        with open(out_path, "w") as f:
            json.dump(node_data, f, indent=2)

        files.append(out_path)
        print(f"[Firebase] Guardado logs de {node_id} → {out_path}")

    return base_dir, files

if __name__ == "__main__":
    connect_firebase()
    logs_dir, files = fetch_all_logs()
    if files:
        print(f"\n[Analyzer] Iniciando análisis global de {len(files)} nodos...")
        analyze_dir(logs_dir)
    else:
        print("[Analyzer] No hay archivos para analizar.")
