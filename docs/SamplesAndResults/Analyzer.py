import os
import json
import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ===========================================================
# --- Utility functions ---
# ===========================================================

def get_cs_label(name: str) -> str:
    """Normalize cryptographic scheme names (e.g., Diffie-Hellman, Kyber)."""
    if not name:
        return "Unknown"

    name_low = name.lower().replace("-", "").replace("_", "")

    if "paillier" in name_low:
        return "Paillier"
    elif "damgardjurik" in name_low:
        return "Damgård-Jurik"
    elif "caope" in name_low:
        return "CA-OPE"
    elif "domainpsi" in name_low:
        return "Domain PSI"
    elif "bfv" == name_low:
        return "BFV"

    # NIKE schemes
    if "diffiehellman" in name_low:
        return "Diffie-Hellman"
    if "p256" in name_low:
        return "P-256"
    if "hybrid" in name_low and "kyber" in name_low and "x25519" in name_low:
        return "Hybrid Kyber-X25519"
    if "kyber" in name_low:
        return "Kyber"
    if "x25519" in name_low or "curve25519" in name_low:
        return "X25519"
    if "classicmceliece" in name_low:
        return "Classic McEliece"
    if "frodo" in name_low:
        return "FrodoKEM"
    if "ntru" in name_low:
        return "NTRU"
    if "bike" in name_low:
        return "BIKE"
    if "hqc" in name_low:
        return "HQC"
    return name


def extract_numeric(x):
    """Extract first numeric value from a string (e.g., '22.5% - 2GHz' → 22.5)."""
    try:
        if isinstance(x, str):
            match = re.findall(r'[\d.]+', x)
            if match:
                return float(match[0])
        return float(x)
    except Exception:
        return np.nan


def weighted_avg(series, weights):
    """Compute weighted average, ignoring NaNs."""
    if not isinstance(series, pd.Series):
        series = pd.Series(series)
    if not isinstance(weights, pd.Series):
        weights = pd.Series(weights)

    valid = series.notna() & weights.notna()
    if not valid.any():
        return np.nan

    try:
        return np.average(series[valid], weights=weights[valid])
    except ZeroDivisionError:
        return np.nan


# ===========================================================
# --- Main Analyzer ---
# ===========================================================

def analyze_activities(filename, folder_path):
    """Aggregate, normalize, and visualize experiment data including slowdown and efficiency metrics."""
    out_dir = os.path.join(folder_path, "AGGREGATED_ANALYSIS")
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n[INFO] Analyzing {filename} ...")

    # ---------------------------------------------------
    # Load JSON data
    # ---------------------------------------------------
    with open(os.path.join(folder_path, filename), "r") as f:
        data = json.load(f)

    if "logs" in data:
        node_logs = data["logs"]
    elif "activities" in data:
        node_logs = {"local_node": data}
    elif isinstance(data, dict) and all(isinstance(v, dict) for v in data.values()):
        node_logs = {"local_node": {"activities": data}}
        print(f"[WARN] Assuming direct activities structure for {filename}")
    else:
        print(f"[ERROR] Unknown format in {filename}, skipping.")
        return

    # ---------------------------------------------------
    # Collect and normalize activity records
    # ---------------------------------------------------
    all_activities = []
    for node_id, node_data in node_logs.items():
        if "activities" not in node_data:
            continue
        node_df = pd.json_normalize(node_data["activities"].values())
        node_df["node_id"] = node_id
        all_activities.append(node_df)

    if not all_activities:
        print(f"[WARN] No activities found in {filename}.")
        return

    df = pd.concat(all_activities, ignore_index=True)

    # ---------------------------------------------------
    # Normalize and clean columns
    # ---------------------------------------------------
    expected_fields = [
        "scheme", "device_type", "peer_device_type", "step", "time",
        "Avg_RAM", "Peak_RAM", "Avg_CPU", "Peak_CPU",
        "Avg_instance_RAM", "Peak_instance_RAM",
        "Avg_instance_CPU", "Peak_instance_CPU",
        "Max_Memory_MB"
    ]
    for col in expected_fields:
        if col not in df.columns:
            df[col] = np.nan

    numeric_cols = [c for c in df.columns if any(x in c for x in ["time", "RAM", "CPU", "Memory"])]
    for col in numeric_cols:
        df[col] = df[col].apply(extract_numeric)

    # Normalize scheme and device fields
    df["scheme"] = df["scheme"].astype(str).apply(get_cs_label)
    df["device_type"] = df["device_type"].fillna("Unknown")
    df["peer_device_type"] = df["peer_device_type"].fillna("Unknown")

    df["role"] = df["step"].apply(
        lambda s: "sender" if isinstance(s, str) and ("FIRST" in s or "THIRD" in s) else "receiver"
    )

    # ---------------------------------------------------
    # Aggregate results (absolute metrics only)
    # ---------------------------------------------------
    grouped_results = []
    group_keys = ["scheme", "device_type", "peer_device_type"]

    for keys, group in df.groupby(group_keys):
        scheme, sender, receiver = keys
        total_time = group["time"].sum()
        weights = group["time"] / total_time if total_time > 0 else np.ones(len(group)) / len(group)

        avg_ram = weighted_avg(group["Avg_RAM"], weights)
        avg_cpu = weighted_avg(group["Avg_CPU"], weights)
        ram_limit = weighted_avg(group["Max_Memory_MB"], weights)
        avg_ram_percent = (avg_ram / ram_limit * 100) if ram_limit and ram_limit > 0 else np.nan

        grouped_results.append({
            "scheme": scheme,
            "from": sender,
            "to": receiver,
            "total_time": total_time,
            "avg_ram_mb": avg_ram,
            "avg_ram_percent": avg_ram_percent,
            "peak_ram_mb": group["Peak_RAM"].max(),
            "avg_cpu_percent": avg_cpu,
            "peak_cpu_percent": group["Peak_CPU"].max(),
            "avg_instance_ram_mb": weighted_avg(group["Avg_instance_RAM"], weights),
            "avg_instance_cpu_percent": weighted_avg(group["Avg_instance_CPU"], weights),
            "executions": len(group),
        })

    results = pd.DataFrame(grouped_results)
    results["link"] = results["from"] + "→" + results["to"]

    # ---------------------------------------------------
    # Derived metrics
    # ---------------------------------------------------
    # Efficiency = CPU% per second (higher = better)
    results["efficiency_index"] = results["avg_cpu_percent"] / results["total_time"]

    # ---------------------------------------------------
    # Slowdown ratios (per algorithm)
    # ---------------------------------------------------
    slowdown_data = (
        results.pivot_table(index="scheme", columns="from", values="total_time", aggfunc="mean")
        .fillna(np.nan)
    )
    if "WS" in slowdown_data.columns:
        for device in ["Android", "IoT"]:
            if device in slowdown_data.columns:
                results.loc[results["from"] == device, "slowdown_vs_WS"] = (
                    results.loc[results["from"] == device, "total_time"]
                    / slowdown_data.loc[results["scheme"], "WS"].values
                )

    # ---------------------------------------------------
    # Save extended CSV
    # ---------------------------------------------------
    csv_file = os.path.join(out_dir, f"{os.path.splitext(filename)[0]}_results_extended.csv")
    results.to_csv(csv_file, index=False)
    print(f"[INFO] Saved extended aggregated results → {csv_file}")

    # ---------------------------------------------------
    # Visualization
    # ---------------------------------------------------
    sns.set(style="whitegrid", font_scale=1.15)
    cmap = plt.get_cmap("tab10")

    # ========== 1. Efficiency ranking ==========
    plt.figure(figsize=(10, 6))
    eff_sorted = results.groupby("scheme")["efficiency_index"].mean().sort_values(ascending=False)
    eff_sorted.plot(kind="barh", color=cmap(2))
    plt.xlabel("Efficiency Index (CPU% / sec)")
    plt.title("Algorithm Efficiency Ranking (Across All Devices)")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "efficiency_ranking.png"))
    plt.close()

    # ========== 2. Slowdown per algorithm (WS baseline) ==========
    slowdown_pivot = slowdown_data.div(slowdown_data["WS"], axis=0)
    slowdown_pivot = slowdown_pivot.drop(columns=["WS"], errors="ignore")
    if not slowdown_pivot.empty:
        plt.figure(figsize=(10, 6))
        sns.heatmap(slowdown_pivot, annot=True, fmt=".2f", cmap="Reds")
        plt.title("Slowdown Factor vs WS — Algorithm × Device")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "heatmap_slowdown_vs_WS.png"))
        plt.close()

    # ========== 3. RAM usage percentage ==========
    ram_percent_pivot = results.pivot_table(index="scheme", columns="from", values="avg_ram_percent", aggfunc="mean")
    if not ram_percent_pivot.empty:
        plt.figure(figsize=(10, 6))
        sns.heatmap(ram_percent_pivot, annot=True, fmt=".1f", cmap="PuBuGn")
        plt.title("Average RAM Usage (%) — Algorithm × Device")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "heatmap_ram_percent_per_device.png"))
        plt.close()

    # ========== 4. Efficiency heatmap ==========
    eff_pivot = results.pivot_table(index="scheme", columns="from", values="efficiency_index", aggfunc="mean")
    if not eff_pivot.empty:
        plt.figure(figsize=(10, 6))
        sns.heatmap(eff_pivot, annot=True, fmt=".2f", cmap="YlGnBu")
        plt.title("Efficiency Index — Algorithm × Device")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "heatmap_efficiency_per_device.png"))
        plt.close()

    print(f"[INFO] Extended analysis complete → {out_dir}")


# ===========================================================
# --- Entry point ---
# ===========================================================

if __name__ == "__main__":
    base_dir = "Experiments"

    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".json"):
                print("=========================================")
                print(f"Analyzing {file} in {root}")
                analyze_activities(file, root + "/")
