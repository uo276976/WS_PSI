import os
import json
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.ticker as mticker
from suitability_config import suitability_rules

mticker.Locator.MAXTICKS = 500

sns.set(style="whitegrid", font_scale=1.05)

DEVICE_ORDER = ["IoT", "Android", "WS", "UNIQUE"]
DEVICE_COLORS = {"IoT": "#2ca02c", "Android": "#ff7f0e", "WS": "#1f77b4", "UNIQUE": "#9467bd"}  # verde, naranja, azul, púrpura
LINKS_ORDER = [
    f"{a} → {b}" for a in DEVICE_ORDER for b in DEVICE_ORDER
    if (a == "UNIQUE" and b == "UNIQUE") or (a != "UNIQUE" and b != "UNIQUE")
]

NIKE_SCHEMES = [
    "Diffie-Hellman", "Diffie-Hellman-8192", "Kyber", "ClassicMcEliece", "FrodoKEM",
    "sntrup761", "BIKE-L1", "HQC-192", "X25519", "P-256",
    "Hybrid-Kyber-X25519", "P-384", "secp256k1", "X448", "RSA"
]
NON_NIKE_SCHEMES = [
    "Paillier",
    "Damgard-Jurik",
    "CAOPE",
    "DomainPSI",
    "BFV",
]

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
            device_type = a.get("device_type", "Unknown")
            scheme = a.get("scheme", "Unknown")
            if device_type in {"Unknown", "TEST"} or scheme in {"Alice", "Bob"}:
                continue
            rows.append({
                "scheme": scheme,
                "category": a.get("category", "Unknown"),
                "device_type": device_type,
                "peer_device_type": a.get("peer_device_type", "Unknown"),
                "step": a.get("step", "Unknown"),
                "time": float(a.get("time", 0.0)),
                "cpu": parse_cpu(a.get("Avg_instance_CPU")),
                "ram": parse_ram_fraction(a.get("Avg_instance_RAM")),
                "peak_cpu": parse_cpu(a.get("Peak_instance_CPU", 0.0)),
                "peak_ram": parse_ram_fraction(a.get("Peak_instance_RAM", "0MB / 1MB")),
                "timestamp": a.get("timestamp", None),
                "key_size_mb": float(a.get("key_size_mb", 0.0))
            })
        except Exception:
            continue
    return rows

def _collect_traces(node_json):
    traces_obj = node_json.get("traces", {})
    if not traces_obj:
        return []

    if isinstance(traces_obj, dict):
        traces_iter = traces_obj.values()
    elif isinstance(traces_obj, list):
        traces_iter = traces_obj
    else:
        return []

    rows = []
    for trace in traces_iter:
        try:
            scheme = trace.get("scheme", "Unknown")
            device_type = trace.get("device_type", "Unknown")
            if device_type in {"Unknown", "TEST"} or scheme in {"Alice", "Bob"}:
                continue

            ts_list = trace.get("timestamps", []) or []
            cpu_list = trace.get("cpu", []) or []
            ram_list = trace.get("ram", []) or []

            for ts, cpu, ram in zip(ts_list, cpu_list, ram_list):
                if isinstance(ts, (int, float)):
                    ts_parsed = pd.to_datetime(ts, unit="s", utc=True, errors="coerce")
                else:
                    ts_str = str(ts).rstrip("Z")
                    ts_parsed = pd.to_datetime(ts_str, utc=True, errors="coerce")

                rows.append({
                    "scheme": scheme,
                    "device_type": device_type,
                    "timestamp": ts_parsed,
                    "cpu": float(cpu),
                    "ram": float(ram),
                })
        except Exception:
            continue
    return rows

def load_all_logs(in_dir):
    """Concatena todos los *.json del directorio (excluye /analysis)."""
    all_rows = []
    all_traces = []
    for path in glob.glob(os.path.join(in_dir, "*.json")):
        if os.path.basename(os.path.dirname(path)) == "analysis":
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
            all_rows.extend(_collect_rows(data))
            all_traces.extend(_collect_traces(data))
        except Exception:
            continue
    df = pd.DataFrame(all_rows)
    df_traces = pd.DataFrame(all_traces)
    return df, df_traces

def analyze_dir(in_dir):
    df, df_traces = load_all_logs(in_dir)
    
    if df.empty:
        print("[WARN] No se encontraron actividades válidas.")
        return

    df_all = df.copy()

    # Filter for NIKE-only schemes (for all general plots)
    df_nike = df[df["scheme"].isin(NIKE_SCHEMES)].copy()
    df_hist = df_nike[df_nike["scheme"] != "Diffie-Hellman-8192"].copy()

    out_dir = os.path.join(in_dir, "analysis")
    os.makedirs(out_dir, exist_ok=True)
    
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # HEATMAPS
    df_nike["link"] = df_nike["device_type"] + " → " + df_nike["peer_device_type"]

    heat = (
        df_nike.groupby(["scheme", "device_type", "peer_device_type"])
            .agg(time=("time", "mean"),
                cpu=("cpu", "mean"),
                ram=("ram", "mean"))
            .reset_index()
    )
    heat = heat[
        (heat["device_type"] == "UNIQUE") & (heat["peer_device_type"] == "UNIQUE")
        | ((heat["device_type"] != "UNIQUE") & (heat["peer_device_type"] != "UNIQUE"))
    ]
    heat["link"] = heat["device_type"] + " → " + heat["peer_device_type"]
    all_schemes = sorted(heat["scheme"].unique().tolist())

    metrics_cfg = {
        "time": {
            "title": "Tiempo promedio (s)",
            "cmap": "RdBu_r",  # rojo (malo) → azul (bueno)
            "vmin": 0.0,
            "vmax": 2.0 
        },
        "cpu": {
            "title": "CPU promedio (%)",
            "cmap": "RdBu_r",
            "vmin": 0.0,
            "vmax": 100.0
        },
        "ram": {
            "title": "RAM promedio (fracción usada)",
            "cmap": "RdBu_r",
            "vmin": 0.0,
            "vmax": 1.0
        }
    }

    for metric, cfg in metrics_cfg.items():
        title, cmap = cfg["title"], cfg["cmap"]
        vmin, vmax = cfg["vmin"], cfg["vmax"]

        grid = (
            heat.pivot_table(index="scheme", columns="link", values=metric, aggfunc="mean")
                .reindex(index=all_schemes, columns=LINKS_ORDER)
                .astype(float)
        )

        plt.figure(figsize=(14, 6))
        ax = sns.heatmap(
            grid,
            annot=True, fmt=".3f", cmap=cmap,
            cbar_kws={"label": title},
            linewidths=1.0, linecolor="gray",
            vmin=vmin, vmax=vmax
        )
        plt.title(f"{title} por combinación de dispositivos", fontsize=13)
        plt.xlabel("Combinación de dispositivos")
        plt.ylabel("Algoritmo / Esquema")
        plt.xticks(rotation=45, ha="right")

        ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
        ax.grid(which="minor", axis="y", linestyle=":", linewidth=0.4, alpha=0.3)

        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f"global_{metric}_heatmap.png"))
        plt.close()

    # HISTOGRAMAS COMBINADOS POR DEVICE
    dev_summary = (
        df_hist.groupby(["scheme", "device_type"])
            .agg(time=("time", "mean"),
                    cpu=("cpu", "mean"),
                    ram=("ram", "mean"),
                    peak_cpu=("peak_cpu", "max"),
                    peak_ram=("peak_ram", "max"))
            .reset_index()
    )
    
    for metric, (title, cmap, *_) in metrics_cfg.items():
        plt.figure(figsize=(14, 6))
        ax = sns.barplot(
            data=dev_summary,
            x="scheme", y=metric,
            hue="device_type",
            hue_order=DEVICE_ORDER,
            palette=DEVICE_COLORS,
            errorbar=None
        )

        plt.title(f"{title} promedio por esquema y tipo de dispositivo")
        plt.xlabel("Algoritmo / Esquema")
        plt.ylabel(title)
        plt.xticks(rotation=45, ha="right")

        handles, labels = ax.get_legend_handles_labels()
        if labels:
            plt.legend(title="Tipo de dispositivo", loc="best", frameon=True)

        ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
        ax.grid(which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.6)
        ax.grid(which="minor", axis="y", linestyle=":", linewidth=0.5, alpha=0.3)

        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f"global_{metric}_by_device.png"))
        plt.close()

    # Métricas de picos (CPU y RAM)
    for metric, label in [
        ("peak_cpu", "Pico máximo de CPU (%)"),
        ("peak_ram", "Pico máximo de RAM (fracción usada)")
    ]:
        plt.figure(figsize=(14, 6))
        ax = sns.barplot(
            data=dev_summary,
            x="scheme", y=metric,
            hue="device_type",
            hue_order=DEVICE_ORDER,
            palette=DEVICE_COLORS,
            errorbar=None
        )

        plt.title(f"{label} por esquema y tipo de dispositivo")
        plt.xlabel("Algoritmo / Esquema")
        plt.ylabel(label)
        plt.xticks(rotation=45, ha="right")

        handles, labels = ax.get_legend_handles_labels()
        if labels:
            plt.legend(title="Tipo de dispositivo", loc="best", frameon=True)

        ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
        plt.ylim(0, 1)

        ax.grid(which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.6)
        ax.grid(which="minor", axis="y", linestyle=":", linewidth=0.4, alpha=0.3)

        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f"global_{metric}_by_device.png"))
        plt.close()
    
    unique_schemes = sorted(df["scheme"].unique())
    for scheme in unique_schemes:
        subset = dev_summary[dev_summary["scheme"] == scheme]
        plt.figure(figsize=(7, 5))
        ax = sns.barplot(
            data=subset,
            x="device_type", y="time",
            hue="device_type",
            hue_order=DEVICE_ORDER,
            palette=DEVICE_COLORS,
            order=DEVICE_ORDER,
            errorbar=None
        )
        plt.title(f"Tiempo promedio del esquema {scheme} por dispositivo")
        plt.xlabel("Tipo de dispositivo")
        plt.ylabel("Tiempo promedio (s)")

        ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
        ax.grid(which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.6)
        ax.grid(which="minor", axis="y", linestyle=":", linewidth=0.4, alpha=0.3)

        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f"{scheme}_by_device_time.png"))
        plt.close()
        
    # Comparativa promedio vs pico de CPU por dispositivo
    for device in DEVICE_ORDER:
        subset = dev_summary[dev_summary["device_type"] == device]
        plt.figure(figsize=(8, 5))
        width = 0.35
        x = np.arange(len(subset["scheme"]))
        plt.bar(x - width/2, subset["cpu"], width, label="CPU promedio", color="#4C72B0")
        plt.bar(x + width/2, subset["peak_cpu"], width, label="CPU pico", color="#DD8452")
        plt.xticks(x, subset["scheme"], rotation=45, ha="right")
        plt.title(f"CPU promedio vs pico - {device}")
        plt.ylabel("Uso de CPU (%)")
        plt.legend(frameon=True)

        plt.grid(axis="y", which="major", linestyle="--", linewidth=0.8, alpha=0.6)
        plt.grid(axis="y", which="minor", linestyle=":", linewidth=0.4, alpha=0.3)
        plt.gca().yaxis.set_minor_locator(plt.MultipleLocator(5))

        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f"{device}_cpu_avg_vs_peak.png"))
        plt.close()


    # TRAZAS TEMPORALES
    if not df_traces.empty:
        trace_dir = os.path.join(out_dir, "temporal_traces")
        os.makedirs(trace_dir, exist_ok=True)

        df_traces = df_traces.sort_values("timestamp")

        for scheme in sorted(df_traces["scheme"].unique()):
            subset = df_traces[df_traces["scheme"] == scheme]
            if subset.empty:
                continue

            # Generar dos versiones: solo UNIQUE y resto
            for group_name, allowed_devices in [("UNIQUE", ["UNIQUE"]), ("non_UNIQUE", ["IoT", "Android", "WS"])]:
                group_subset = subset[subset["device_type"].isin(allowed_devices)]
                if group_subset.empty:
                    continue

                for metric, label in [("cpu", "CPU promedio (%)"), ("ram", "RAM (fracción usada)")]:
                    if metric not in group_subset.columns or group_subset[metric].dropna().empty:
                        continue

                    plt.figure(figsize=(12, 6))
                    ax = sns.lineplot(
                        data=group_subset,
                        x="timestamp",
                        y=metric,
                        hue="device_type",
                        hue_order=[d for d in DEVICE_ORDER if d in group_subset["device_type"].unique()],
                        palette=DEVICE_COLORS,
                        linewidth=1.6
                    )

                    plt.title(f"Evolución temporal de {label} — {scheme} ({group_name})")
                    plt.xlabel("Tiempo")
                    plt.ylabel(label)

                    # Solo mostrar dispositivos presentes
                    handles, labels = ax.get_legend_handles_labels()
                    if labels:
                        plt.legend(title="Dispositivo", loc="best", frameon=True)
                    else:
                        ax.get_legend().remove()

                    ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
                    ax.grid(which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.6)
                    ax.grid(which="minor", axis="y", linestyle=":", linewidth=0.4, alpha=0.3)
                    ax.grid(which="major", axis="x", linestyle=":", linewidth=0.4, alpha=0.3)

                    plt.tight_layout()
                    fname = f"{scheme}_{group_name}_{metric}_trace.png"
                    plt.savefig(os.path.join(trace_dir, fname))
                    plt.close()

        print(f"[OK] Trazas temporales generadas en {trace_dir}")
    else:
        print("[WARN] No se encontraron trazas temporales.")

    # HISTOGRAMA DE TAMAÑO DE CLAVE POR ALGORITMO 
    print("[INFO] Generando histograma de tamaño de clave por algoritmo...")

    # Key size summary directly from df
    key_summary_df = (
        df[df["key_size_mb"] > 0]
        .groupby("scheme")
        .agg(max_key_size=("key_size_mb", "max"))
        .reset_index()
    )

    if not key_summary_df.empty:
        plt.figure(figsize=(10, 6))
        ax = sns.barplot(
            data=key_summary_df.sort_values("max_key_size", ascending=False),
            x="scheme", y="max_key_size",
            palette="viridis", errorbar=None
        )

        plt.title("Tamaño máximo de clave por algoritmo (MB)")
        plt.xlabel("Algoritmo / Esquema")
        plt.ylabel("Tamaño de clave máximo (MB)")
        plt.xticks(rotation=45, ha="right")
        ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
        ax.grid(which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.6)
        ax.grid(which="minor", axis="y", linestyle=":", linewidth=0.4, alpha=0.3)

        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "key_size_histogram.png"))
        plt.close()

        key_summary_df.to_json(os.path.join(out_dir, "key_size_summary.json"), orient="records", indent=2)
        print(f"[OK] Histograma de tamaño de clave generado → {os.path.join(out_dir, 'key_size_summary.json')}")
    else:
        print("[WARN] No se encontraron datos de key_size_mb en los logs.")
        
    try:
        key_json_path = os.path.join(out_dir, "key_size_summary.json")
        if os.path.exists(key_json_path):
            key_summary_df = pd.read_json(key_json_path)
            key_summary_df = key_summary_df[["scheme", "max_key_size"]]
        else:
            key_summary_df = pd.DataFrame(columns=["scheme", "max_key_size"])
    except Exception:
        key_summary_df = pd.DataFrame(columns=["scheme", "max_key_size"])

    # RESUMEN GLOBAL COMPARATIVO POR DEVICE
    global_summary = (
        df_all.groupby("device_type")
        .agg(avg_time=("time", "mean"),
            avg_cpu=("cpu", "mean"),
            avg_ram=("ram", "mean"))
        .reindex(DEVICE_ORDER)
        .reset_index()
    )

    by_device_scheme_df = (
        df_nike.groupby(["device_type", "scheme"])
        .agg(
            avg_time=("time", "mean"),
            avg_cpu=("cpu", "mean"),
            avg_ram=("ram", "mean"),
            samples=("time", "count")
        )
        .reset_index()
        .sort_values(["device_type", "avg_time"])
    )

    global_means = {
        "avg_time": df_all["time"].mean(),
        "avg_cpu": df_all["cpu"].mean(),
        "avg_ram": df_all["ram"].mean(),
        "total_samples": len(df_all),
        "device_types": df_all["device_type"].nunique(),
        "schemes": df_all["scheme"].nunique()
    }

    output_data = {
        "overall": global_means,
        "by_device": global_summary.to_dict(orient="records"),
        "by_device_by_scheme": by_device_scheme_df.to_dict(orient="records")
    }

    out_json = os.path.join(out_dir, "global_summary.json")
    with open(out_json, "w") as f:
        json.dump(output_data, f, indent=2)

    print(f"[OK] Resumen global exportado a {out_json}")

    perf_df = (
        df.groupby("device_type")
        .agg(
            avg_time=("time", "mean"),
            avg_cpu=("cpu", "mean"),
            avg_ram=("ram", "mean")
        )
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

    # Función genérica para todas las barras resumidas
    def plot_device_summary(df, ycol, title, ylabel, filename, step=5, ylim=None):
        plt.figure(figsize=(7, 5))
        ax = sns.barplot(
            data=df,
            x="device_type", y=ycol,
            hue="device_type",
            hue_order=DEVICE_ORDER,
            palette=DEVICE_COLORS,
            order=DEVICE_ORDER,
            errorbar=None
        )
        plt.title(title)
        plt.xlabel("Tipo de dispositivo")
        plt.ylabel(ylabel)
        handles, labels = ax.get_legend_handles_labels()
        if labels:
            plt.legend(title="Tipo de dispositivo", loc="best", frameon=True)

        # Ejes y rejilla
        if ylim:
            plt.ylim(ylim)
            
        ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
        ax.grid(which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.6)
        ax.grid(which="minor", axis="y", linestyle=":", linewidth=0.4, alpha=0.3)

        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, filename))
        plt.close()

    # Llamadas a la función
    plot_device_summary(
        global_summary, "avg_time",
        "Tiempo promedio por tipo de dispositivo (s)",
        "Tiempo promedio (s)",
        "global_summary_time.png", step=0.01
    )

    plot_device_summary(
        global_summary, "avg_cpu",
        "CPU promedio por tipo de dispositivo (%)",
        "CPU promedio (%)",
        "global_summary_cpu.png", step=5
    )

    plot_device_summary(
        global_summary, "avg_ram",
        "RAM promedio por tipo de dispositivo (fracción usada)",
        "RAM promedio (fracción usada)",
        "global_summary_ram.png", step=0.05, ylim=(0, 1)
    )

    plot_device_summary(
        perf_df, "performance_index",
        "Índice de rendimiento general (Tiempo + CPU + RAM)",
        "Puntuación normalizada (0-1, más alto es mejor)",
        "global_performance_index.png", step=0.1, ylim=(0, 1)
    )

    # Already grouped earlier
    by_device_scheme_df = (
        df_nike.groupby(["device_type", "scheme"])
        .agg(
            avg_time=("time", "mean"),
            avg_cpu=("cpu", "mean"),
            avg_ram=("ram", "mean"),
            samples=("time", "count")
        )
        .reset_index()
    )

    # Join key size in one step
    by_device_scheme_df = by_device_scheme_df.merge(key_summary_df, on="scheme", how="left")

    def assess(row):
        limits = suitability_rules.get(row["device_type"], {})
        reasons = []
        ok = True

        if "time" in limits and row["avg_time"] > limits["time"]:
            ok = False
            reasons.append(f"Tiempo {row['avg_time']:.3f}s > {limits['time']}s")
        if "cpu" in limits and row["avg_cpu"] > limits["cpu"]:
            ok = False
            reasons.append(f"CPU {row['avg_cpu']:.1f}% > {limits['cpu']}%")
        if "ram" in limits and row["avg_ram"] > limits["ram"]:
            ok = False
            reasons.append(f"RAM {row['avg_ram']:.2f} > {limits['ram']}")
        if "key_size" in limits and not pd.isna(row.get("max_key_size", None)):
            if row["max_key_size"] > limits["key_size"]:
                ok = False
                reasons.append(f"Clave {row['max_key_size']:.3f}MB > {limits['key_size']}MB")

        verdict = "Viable" if ok else "No viable"
        reason = "; ".join(reasons) if reasons else "Dentro de umbrales esperados"
        return pd.Series({"verdict": verdict, "reason": reason})

    suitability_df = by_device_scheme_df.join(by_device_scheme_df.apply(assess, axis=1))
    suitability_df.to_json(os.path.join(out_dir, "suitability_table.json"), orient="records", indent=2)
    suitability_df.to_csv(os.path.join(out_dir, "suitability_table.csv"), index=False)

    print(f"[OK] Suitability table generada → {os.path.join(out_dir, 'suitability_table.json')}")

    print(f"[OK] Análisis completado → {out_dir}")
    print(f"[Resumen global]: {json.dumps(global_means, indent=2)}")
