import os
import json
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sns.set(style="whitegrid", font_scale=1.05)

DEVICE_ORDER = ["IoT", "Android", "WS"]
DEVICE_COLORS = {"IoT": "#2ca02c", "Android": "#ff7f0e", "WS": "#1f77b4"}  # verde, naranja, azul
LINKS_ORDER = [f"{a} → {b}" for a in DEVICE_ORDER for b in DEVICE_ORDER]

# -----------------------
# Helpers
# -----------------------

def parse_cpu(val):
    if isinstance(val, str):
        val = val.strip()
        if val.endswith("%"):
            val = val[:-1]
    try:
        return float(val)
    except Exception:
        return 0.0


def parse_ram_fraction(val):
    """'Avg_instance_RAM': '108.16MB / 256.0MB' -> return fraction used (0..1)."""
    if not isinstance(val, str):
        return 0.0
    try:
        txt = val.replace("MB", "").strip()
        used_s, total_s = [x.strip() for x in txt.split("/", 1)]
        used = float(used_s)
        total = float(total_s)
        return used / total if total > 0 else 0.0
    except Exception:
        return 0.0


def _collect_rows(node_json):
    acts = node_json.get("activities", {})
    rows = []
    for a in acts.values():
        try:
            rows.append({
                "scheme": a.get("scheme", "Unknown"),
                "category": a.get("category", "Unknown"),
                "device_type": a.get("device_type", "Unknown"),
                "peer_device_type": a.get("peer_device_type", "Unknown"),
                "step": a.get("step", "Unknown"),
                "time": float(a.get("time", 0.0)),
                "cpu": parse_cpu(a.get("Avg_instance_CPU")),
                "ram": parse_ram_fraction(a.get("Avg_instance_RAM")),
            })
        except Exception:
            continue
    return rows


def load_all_logs(in_dir):
    """Concatena todos los *.json del directorio (excluye /analysis)."""
    all_rows = []
    for path in glob.glob(os.path.join(in_dir, "*.json")):
        if os.path.basename(os.path.dirname(path)) == "analysis":
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
            all_rows.extend(_collect_rows(data))
        except Exception:
            continue
    return pd.DataFrame(all_rows)

# -----------------------
# Analyzer
# -----------------------

def analyze_dir(in_dir):
    df = load_all_logs(in_dir)
    if df.empty:
        print("[WARN] No se encontraron actividades válidas.")
        return

    out_dir = os.path.join(in_dir, "analysis")
    os.makedirs(out_dir, exist_ok=True)

    # ==============================================================
    # HEATMAPS GLOBALES
    # ==============================================================
    df["link"] = df["device_type"] + " → " + df["peer_device_type"]

    heat = (
        df.groupby(["scheme", "device_type", "peer_device_type"])
          .agg(time=("time", "mean"),
               cpu=("cpu", "mean"),
               ram=("ram", "mean"))
          .reset_index()
    )
    heat["link"] = heat["device_type"] + " → " + heat["peer_device_type"]
    all_schemes = sorted(heat["scheme"].unique().tolist())

    metrics_cfg = {
        "time": ("Tiempo promedio (s)", "coolwarm"),
        "cpu": ("CPU promedio (%)", "crest"),
        "ram": ("RAM promedio (fracción usada)", "mako"),
    }

    for metric, (title, cmap) in metrics_cfg.items():
        grid = (
            heat.pivot_table(index="scheme", columns="link", values=metric, aggfunc="mean")
                .reindex(index=all_schemes, columns=LINKS_ORDER)
                .astype(float)
        )
        plt.figure(figsize=(14, 6))
        sns.heatmap(
            grid, annot=True, fmt=".3f", cmap=cmap,
            cbar_kws={"label": title},
            linewidths=0.5, linecolor="white"
        )
        plt.title(f"{title} por combinación de dispositivos", fontsize=13)
        plt.xlabel("Combinación de dispositivos")
        plt.ylabel("Algoritmo / Esquema")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f"global_{metric}_heatmap.png"))
        plt.close()

    # ==============================================================
    # HISTOGRAMAS COMBINADOS POR DEVICE
    # ==============================================================
    dev_summary = (
        df.groupby(["scheme", "device_type"])
          .agg(time=("time", "mean"),
               cpu=("cpu", "mean"),
               ram=("ram", "mean"))
          .reset_index()
    )

    for metric, (title, palette) in metrics_cfg.items():
        plt.figure(figsize=(14, 6))
        sns.barplot(
            data=dev_summary,
            x="scheme", y=metric,
            hue="device_type",
            hue_order=DEVICE_ORDER,
            palette=[DEVICE_COLORS[d] for d in DEVICE_ORDER],
            errorbar=None
        )
        plt.title(f"{title} promedio por esquema y tipo de dispositivo")
        plt.xlabel("Algoritmo / Esquema")
        plt.ylabel(title)
        plt.xticks(rotation=45, ha="right")
        plt.legend(title="Tipo de dispositivo")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f"global_{metric}_by_device.png"))
        plt.close()

    # ==============================================================
    # RESUMEN GLOBAL COMPARATIVO POR DEVICE (una gráfica por métrica)
    # ==============================================================

    global_summary = (
        df.groupby("device_type")
          .agg(avg_time=("time", "mean"),
               avg_cpu=("cpu", "mean"),
               avg_ram=("ram", "mean"))
          .reindex(DEVICE_ORDER)
          .reset_index()
    )

    global_means = {
        "avg_time": df["time"].mean(),
        "avg_cpu": df["cpu"].mean(),
        "avg_ram": df["ram"].mean(),
        "total_samples": len(df),
        "device_types": df["device_type"].nunique(),
        "schemes": df["scheme"].nunique()
    }

    with open(os.path.join(out_dir, "global_summary.json"), "w") as f:
        json.dump({
            "overall": global_means,
            "by_device": global_summary.to_dict(orient="records")
        }, f, indent=2)

    # --- Tiempo promedio por dispositivo ---
    plt.figure(figsize=(7, 5))
    sns.barplot(
        data=global_summary,
        x="device_type", y="avg_time",
        order=DEVICE_ORDER,
        palette=[DEVICE_COLORS[d] for d in DEVICE_ORDER],
        errorbar=None
    )
    plt.title("Tiempo promedio por tipo de dispositivo (s)")
    plt.xlabel("Tipo de dispositivo")
    plt.ylabel("Tiempo promedio (s)")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "global_summary_time.png"))
    plt.close()

    # --- CPU promedio por dispositivo ---
    plt.figure(figsize=(7, 5))
    sns.barplot(
        data=global_summary,
        x="device_type", y="avg_cpu",
        order=DEVICE_ORDER,
        palette=[DEVICE_COLORS[d] for d in DEVICE_ORDER],
        errorbar=None
    )
    plt.title("CPU promedio por tipo de dispositivo (%)")
    plt.xlabel("Tipo de dispositivo")
    plt.ylabel("CPU promedio (%)")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "global_summary_cpu.png"))
    plt.close()

    # --- RAM promedio por dispositivo ---
    plt.figure(figsize=(7, 5))
    sns.barplot(
        data=global_summary,
        x="device_type", y="avg_ram",
        order=DEVICE_ORDER,
        palette=[DEVICE_COLORS[d] for d in DEVICE_ORDER],
        errorbar=None
    )
    plt.title("RAM promedio por tipo de dispositivo (fracción usada)")
    plt.xlabel("Tipo de dispositivo")
    plt.ylabel("RAM promedio (fracción usada)")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "global_summary_ram.png"))
    plt.close()

    # ==============================================================
    # RENDIMIENTO GLOBAL COMBINADO
    # ==============================================================
    # Promedios por device
    perf_df = (
        df.groupby("device_type")
          .agg(avg_time=("time", "mean"),
               avg_cpu=("cpu", "mean"),
               avg_ram=("ram", "mean"))
          .reset_index()
    )

    # Normalización y cálculo de índice
    max_time = perf_df["avg_time"].max() or 1
    perf_df["norm_time"] = 1 - (perf_df["avg_time"] / max_time)
    perf_df["norm_cpu"] = 1 - (perf_df["avg_cpu"] / 100)
    perf_df["norm_ram"] = 1 - perf_df["avg_ram"]

    perf_df["performance_index"] = (
        0.6 * perf_df["norm_time"] + 0.2 * perf_df["norm_cpu"] + 0.2 * perf_df["norm_ram"]
    )

    plt.figure(figsize=(8, 5))
    sns.barplot(
        data=perf_df,
        x="device_type", y="performance_index",
        palette=[DEVICE_COLORS[d] for d in DEVICE_ORDER],
        order=DEVICE_ORDER
    )
    plt.title("Índice de rendimiento general (Tiempo + CPU + RAM)")
    plt.ylabel("Puntuación normalizada (0–1, más alto es mejor)")
    plt.xlabel("Tipo de dispositivo")
    plt.ylim(0, 1)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "global_performance_index.png"))
    plt.close()

    print(f"[OK] Análisis completado → {out_dir}")
    print(f"[Resumen global]: {json.dumps(global_means, indent=2)}")
