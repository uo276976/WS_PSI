import os
import json
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.ticker as mticker

mticker.Locator.MAXTICKS = 500

sns.set(style="whitegrid", font_scale=1.05)

DEVICE_ORDER = ["IoT", "Android", "WS"]
DEVICE_COLORS = {"IoT": "#2ca02c", "Android": "#ff7f0e", "WS": "#1f77b4"}  # verde, naranja, azul
LINKS_ORDER = [f"{a} → {b}" for a in DEVICE_ORDER for b in DEVICE_ORDER]

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
            rows.append({
                "scheme": a.get("scheme", "Unknown"),
                "category": a.get("category", "Unknown"),
                "device_type": a.get("device_type", "Unknown"),
                "peer_device_type": a.get("peer_device_type", "Unknown"),
                "step": a.get("step", "Unknown"),
                "time": float(a.get("time", 0.0)),
                "cpu": parse_cpu(a.get("Avg_instance_CPU")),
                "ram": parse_ram_fraction(a.get("Avg_instance_RAM")),
                "peak_cpu": parse_cpu(a.get("Peak_instance_CPU", 0.0)),
                "peak_ram": parse_ram_fraction(a.get("Peak_instance_RAM", "0MB / 1MB")),
                "timestamp": a.get("timestamp", None)
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


def analyze_dir(in_dir):
    df = load_all_logs(in_dir)
    if df.empty:
        print("[WARN] No se encontraron actividades válidas.")
        return

    df_all = df.copy()

    # Filter for NIKE-only schemes (for all general plots)
    df = df[df["scheme"].isin(NIKE_SCHEMES)].copy()

    out_dir = os.path.join(in_dir, "analysis")
    os.makedirs(out_dir, exist_ok=True)
    
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # HEATMAPS GLOBALES
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
        ax = sns.heatmap(
            grid,
            annot=True, fmt=".3f", cmap=cmap,
            cbar_kws={"label": title},
            linewidths=1.0, linecolor="gray"
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
        df.groupby(["scheme", "device_type"])
          .agg(time=("time", "mean"),
               cpu=("cpu", "mean"),
               ram=("ram", "mean"),
               peak_cpu=("peak_cpu", "max"),
               peak_ram=("peak_ram", "max"))
          .reset_index()
    )
    
    for metric, (title, _) in metrics_cfg.items():
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
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        trace_dir = os.path.join(out_dir, "temporal_traces")
        os.makedirs(trace_dir, exist_ok=True)

        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.sort_values("timestamp")

        palette = {d: DEVICE_COLORS[d] for d in DEVICE_ORDER}

        for scheme in sorted(df["scheme"].unique()):
            subset_scheme = df[df["scheme"] == scheme]
            if subset_scheme.empty:
                continue

            # CPU trace
            plt.figure(figsize=(12, 6))
            ax = sns.lineplot(
                data=subset_scheme,
                x="timestamp",
                y="cpu",
                hue="device_type",
                hue_order=DEVICE_ORDER,
                palette=palette,
                linewidth=1.6
            )
            plt.title(f"Evolución temporal del uso de CPU — {scheme}")
            plt.xlabel("Tiempo")
            plt.ylabel("CPU promedio (%)")
            plt.legend(title="Dispositivo", loc="best", frameon=True)

            ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
            ax.grid(which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.6)
            ax.grid(which="minor", axis="y", linestyle=":", linewidth=0.4, alpha=0.3)
            ax.grid(which="major", axis="x", linestyle=":", linewidth=0.4, alpha=0.3)

            plt.tight_layout()
            plt.savefig(os.path.join(trace_dir, f"{scheme}_cpu_trace.png"))
            plt.close()

            # RAM trace
            plt.figure(figsize=(12, 6))
            ax = sns.lineplot(
                data=subset_scheme,
                x="timestamp",
                y="ram",
                hue="device_type",
                hue_order=DEVICE_ORDER,
                palette=palette,
                linewidth=1.6
            )
            plt.title(f"Evolución temporal del uso de RAM — {scheme}")
            plt.xlabel("Tiempo")
            plt.ylabel("RAM (fracción usada)")
            plt.legend(title="Dispositivo", loc="best", frameon=True)

            ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
            ax.grid(which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.6)
            ax.grid(which="minor", axis="y", linestyle=":", linewidth=0.4, alpha=0.3)
            ax.grid(which="major", axis="x", linestyle=":", linewidth=0.4, alpha=0.3)

            plt.tight_layout()
            plt.savefig(os.path.join(trace_dir, f"{scheme}_ram_trace.png"))
            plt.close()

        print(f"[OK] Trazas temporales generadas en {trace_dir}")

    # HISTOGRAMA DE TAMAÑO DE CLAVE POR ALGORITMO 
    print("[INFO] Generando histograma de tamaño de clave por algoritmo...")

    key_rows = []
    for path in glob.glob(os.path.join(in_dir, "*.json")):
        if os.path.basename(os.path.dirname(path)) == "analysis":
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
            acts = data.get("activities", {})
            for a in acts.values():
                scheme = a.get("scheme", "Unknown")
                key_size = float(a.get("key_size_mb", 0.0))
                msg_size = float(a.get("msg_size_mb", 0.0))
                key_rows.append({"scheme": scheme, "key_size_mb": key_size, "msg_size_mb": msg_size})
        except Exception:
            continue

    key_df = pd.DataFrame(key_rows)
    if not key_df.empty:
        key_summary = (
            key_df.groupby("scheme")
            .agg(max_key_size=("key_size_mb", "max"), max_msg_size=("msg_size_mb", "max"))
            .reset_index()
        )

        plt.figure(figsize=(10, 6))
        ax = sns.barplot(
            data=key_summary.sort_values("max_key_size", ascending=False),
            x="scheme", y="max_key_size",
            palette="viridis", errorbar=None
        )

        # --- Add numeric labels on top of bars ---
        for p in ax.patches:
            height = p.get_height()
            if not np.isnan(height) and height > 0:
                ax.text(
                    p.get_x() + p.get_width() / 2,
                    height + 0.005,  # slightly above bar
                    f"{height:.3f} MB",
                    ha="center", va="bottom",
                    fontsize=9, fontweight="bold", color="black"
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

        # Guardar resumen como JSON
        key_json_path = os.path.join(out_dir, "key_size_summary.json")
        key_summary.to_json(key_json_path, orient="records", indent=2)
        print(f"[OK] Histograma de tamaño de clave generado → {key_json_path}")
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
        df.groupby("device_type")
        .agg(avg_time=("time", "mean"),
            avg_cpu=("cpu", "mean"),
            avg_ram=("ram", "mean"))
        .reindex(DEVICE_ORDER)
        .reset_index()
    )

    by_device_by_scheme = (
        df.groupby(["device_type", "scheme"])
        .agg(
            avg_time=("time", "mean"),
            avg_cpu=("cpu", "mean"),
            avg_ram=("ram", "mean"),
            samples=("time", "count")
        )
        .reset_index()
        .sort_values(["device_type", "avg_time"])
        .to_dict(orient="records")
    )

    global_means = {
        "avg_time": df["time"].mean(),
        "avg_cpu": df["cpu"].mean(),
        "avg_ram": df["ram"].mean(),
        "total_samples": len(df),
        "device_types": df["device_type"].nunique(),
        "schemes": df["scheme"].nunique()
    }

    output_data = {
        "overall": global_means,
        "by_device": global_summary.to_dict(orient="records"),
        "by_device_by_scheme": by_device_by_scheme
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
    
    # --- NIKE vs Non-NIKE comparative analysis ---
    print("[INFO] Generando comparativa Non-NIKE vs Media de NIKEs...")

    # Build dev_summary_all using full data (before filtering)
    dev_summary_all = (
        df_all.groupby(["scheme", "device_type"])
            .agg(time=("time", "mean"),
                cpu=("cpu", "mean"),
                ram=("ram", "mean"))
            .reset_index()
    )

    # Compute NIKE mean excluding DH-8192
    nike_df = dev_summary_all[dev_summary_all["scheme"].isin(NIKE_SCHEMES)]
    if not nike_df.empty:
        nike_mean = nike_df.groupby("device_type")[["time", "cpu", "ram"]].mean().reset_index()
        nike_mean["scheme"] = "NIKE_mean"

        # Merge key sizes if available
        if 'key_summary_df' in locals() and not key_summary_df.empty:
            mean_key = key_summary_df[key_summary_df["scheme"].isin(NIKE_SCHEMES)]["max_key_size"].mean()
            nike_mean["max_key_size"] = mean_key
        else:
            nike_mean["max_key_size"] = np.nan

        compare_df = dev_summary_all[dev_summary_all["scheme"].isin(NON_NIKE_SCHEMES)].copy()

        # Add key sizes
        compare_df = compare_df.merge(key_summary_df, on="scheme", how="left")

        # Append NIKE mean
        compare_df = pd.concat([compare_df, nike_mean], ignore_index=True)

        # Plot per metric
        metrics = {
            "time": "Tiempo promedio (s)",
            "cpu": "CPU promedio (%)",
            "ram": "RAM promedio (fracción usada)",
            "max_key_size": "Tamaño máximo de clave (MB)"
        }

        for metric, label in metrics.items():
            plt.figure(figsize=(10, 6))
            ax = sns.barplot(
                data=compare_df,
                x="scheme", y=metric,
                hue="device_type",
                hue_order=DEVICE_ORDER,
                palette=DEVICE_COLORS,
                errorbar=None
            )

            plt.title(f"{label} — Non-NIKE vs Media de NIKEs")
            plt.xlabel("Algoritmo / Esquema")
            plt.ylabel(label)
            plt.xticks(rotation=45, ha="right")

            # Highlight NIKE mean in gray
            for patch, scheme in zip(ax.patches, compare_df["scheme"]):
                if scheme == "NIKE_mean":
                    patch.set_facecolor("#AAAAAA")

            ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
            ax.grid(which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.6)
            ax.grid(which="minor", axis="y", linestyle=":", linewidth=0.4, alpha=0.3)

            plt.tight_layout()
            plt.savefig(os.path.join(out_dir, f"compare_non_nike_vs_nike_{metric}.png"))
            plt.close()

        print(f"[OK] Comparativas Non-NIKE generadas en {out_dir}")
    else:
        print("[WARN] No se encontraron esquemas NIKE para la comparativa.")


    by_device_scheme_df = pd.DataFrame(by_device_by_scheme)

    by_device_scheme_df = by_device_scheme_df.merge(
        key_summary_df,
        on="scheme",
        how="left"
    )

    suitability_rules = {
        "IoT": {
            "time": 0.5,
            "cpu": 65,
            "ram": 0.80,
            "key_size": 0.10   # 100 KB max
        },
        "Android": {
            "time": 0.2,
            "cpu": 80,
            "ram": 0.30,
            "key_size": 0.50   # 500 KB max
        },
        "WS": {
            "time": 0.1,
            "cpu": 90,
            "ram": 0.70,
            "key_size": 5.00   # 5 MB max
        }
    }

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
    suitability_out = os.path.join(out_dir, "suitability_table.json")
    suitability_df.to_json(suitability_out, orient="records", indent=2)
    suitability_csv = os.path.join(out_dir, "suitability_table.csv")
    suitability_df.to_csv(suitability_csv, index=False)

    print(f"[OK] Suitability table generada → {suitability_out}")

    print(f"[OK] Análisis completado → {out_dir}")
    print(f"[Resumen global]: {json.dumps(global_means, indent=2)}")
