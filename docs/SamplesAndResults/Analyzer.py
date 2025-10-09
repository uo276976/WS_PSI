import os
import json
import re

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib import ticker
from numpy import nan


def get_cs_label(name: str) -> str:
    """
    Return a consistent, descriptive label for the cryptographic scheme given by 'name'.
    Recognizes all schemes defined in CryptoImplementation, including new NIKE schemes.
    """
    if not name:
        return "Unknown"

    name_low = name.lower().replace("-", "").replace("_", "")

    # PSI-CA schemes
    if "paillier" in name_low:
        return "Paillier"
    elif "damgardjurik" in name_low or "damgård" in name_low:
        return "Damgård-Jurik"
    elif "caope" in name_low:
        return "CA-OPE"

    # PSI-Domain scheme
    elif "domainpsi" in name_low:
        return "Domain PSI"

    # OPE scheme
    elif name_low == "bfv":
        return "BFV"

    # NIKE schemes
    elif "diffie-hellman" in name_low or "diffiehellman" in name_low:
        return "Diffie-Hellman"

    elif name_low == "x25519" or name_low == "curve25519":
        return "X25519"

    elif name_low == "p256" or name_low == "p-256":
        return "P-256"

    elif "kyber" in name_low:
        return "Kyber"

    elif "classicmceliece" in name_low or "classic-mceliece" in name_low:
        return "Classic McEliece"

    elif "frodo" in name_low:
        return "FrodoKEM"

    elif name_low == "ntru":
        return "NTRU"

    elif "bike" in name_low:
        return "BIKE"

    elif "hqc" in name_low:
        return "HQC"

    elif "hybrid" in name_low and "kyber" in name_low and "x25519" in name_low:
        return "Hybrid Kyber/X25519"

    # Fallback: use the original name if no mapping was found
    return name


def get_label(name: str) -> str:
    """
    Return a plot label for a given activity 'name', combining scheme label and context.
    Adds platform context (Android, WS, IoT) and uses get_cs_label for the scheme part.
    """
    if not name:  # Fallback if name is empty/None
        return "Unknown"
    base_name = name.strip()
    platform_suffix = ""

    # Normalize for platform types
    if any(base_name.endswith(suffix) for suffix in [" Android", "-Android", "_Android"]):
        base_name = re.sub(r'[-_ ]?Android$', '', base_name)
        platform_suffix = " (Android)"
    elif any(base_name.endswith(suffix) for suffix in [" WS", "-WS", "_WS"]):
        base_name = re.sub(r'[-_ ]?WS$', '', base_name)
        platform_suffix = " (WS)"
    elif any(base_name.endswith(suffix) for suffix in [" IoT", "-IoT", "_IoT"]):
        base_name = re.sub(r'[-_ ]?IoT$', '', base_name)
        platform_suffix = " (IoT)"

    scheme_label = get_cs_label(base_name)
    return f"{scheme_label}{platform_suffix}"


def analyze_activities(ftba, fp):
    output_folder = ftba.split('.')[0].upper()
    folder_path = fp + output_folder

    with open(fp + ftba, 'r') as f:  # r porque se va a leer
        data = json.load(f)
        # Crear un DataFrame vacío para almacenar los datos
        df_activities = pd.DataFrame()

        if "logs" in data:
            node_logs = data["logs"]
        elif "activities" in data:
            # single node JSON (from fetch_all_logs)
            node_logs = {"local_node": data}
        else:
            # Try to detect if data itself looks like activities
            if isinstance(data, dict) and all(isinstance(v, dict) for v in data.values()):
                # probably a direct node dump: treat it as activities
                node_logs = {"local_node": {"activities": data}}
                print(f"[WARN] Assuming direct activities structure for {ftba}")
            else:
                print(f"[ERROR] Unknown JSON format in {ftba}, skipping file.")
                return  # skip instead of raising an exception

        # Iterar sobre cada identificador en los datos
        for identificador, node_data in node_logs.items():
             if "activities" in node_data:
                # Extraer las actividades para el identificador actual
                activities = node_data["activities"]

                # Convertir las actividades en un DataFrame
                df = pd.json_normalize(activities.values())

                # Agregar una columna para el identificador actual
                df['id'] = identificador

                # Convertir la columna de timestamp a datetime
                # --- Handle missing timestamp column ---
                time_col = None
                for candidate in ["timestamp", "time", "log_time", "created_at", "Timestamp"]:
                    if candidate in df.columns:
                        time_col = candidate
                        break

                if time_col is None:
                    print(f"[WARN] No timestamp column found in {ftba} (id: {identificador}), skipping this node.")
                    continue

                # Convert to datetime safely
                df['timestamp'] = pd.to_datetime(df[time_col], errors='coerce', utc=True)

                # Coerce para que ponga NaT si no puede convertir

                # Debug: Verificar datos antes de concatenar
                if df['timestamp'].isna().any():
                    print(f"Advertencia: Identificador {identificador} tiene valores NaT antes de concatenar.")
                else:
                    print(f"Identificador {identificador} no tiene valores NaT antes de concatenar.")

                # Concatenar el DataFrame actual con el DataFrame que contiene todas las actividades
                df_activities = pd.concat([df_activities, df], ignore_index=True)

                if df_activities['timestamp'].isna().any():
                    print("Advertencia: Hay valores NaT en 'timestamp' después de concatenar.")
                else:
                    print("No hay valores NaT en 'timestamp' después de concatenar.")

    # Calcula el tiempo total
    # --- Skip files with no valid timestamps ---
    if df_activities.empty or 'timestamp' not in df_activities.columns:
        print(f"[WARN] No valid timestamp data found in {ftba}, skipping time-based analysis.")
        return

    # Calcula el tiempo total
    tiempo_total = df_activities['timestamp'].max() - df_activities['timestamp'].min()
    print(f'Tiempo total: {tiempo_total}')

    # Ordena el DataFrame por el timestamp
    df_activities = df_activities.sort_values('timestamp')

    # Agrupa los datos por el código de actividad
    # --- Group by both scheme and device type ---
    if 'scheme' in df_activities.columns:
        group_key = ['scheme', 'device_type']
    else:
        group_key = ['activity_code', 'device_type']

    grouped = df_activities.groupby(group_key)

    # Crea un DataFrame para almacenar los resultados
    results = pd.DataFrame(
        columns=['device_type', 'activity_code', 'media_tiempo', 'media_ram', 'min_ram', 'max_ram', 'media_cpu',
                 'min_cpu', 'max_cpu', 'instance_ram', 'instance_cpu', 'instance_min_ram', 'instance_max_ram',
                 'instance_min_cpu', 'instance_max_cpu', 'cpu_time', 'min_cpu_time', 'max_cpu_time', 'Ciphertext_size'])

    # Calcula las medias y los picos para cada grupo
    for name, group in grouped:
        if group.empty:
            continue

        # --- Normalize and clean columns ---
        # Device type is now explicitly logged
        device_type = group.get('device_type', group.get('Details', 'Unknown'))
        if isinstance(device_type, pd.Series):
            device_type = device_type.iloc[0]

        # Parse Ciphertext size if present
        if 'Ciphertext_size' in group.columns:
            group['Ciphertext_size'] = (
                group['Ciphertext_size']
                .astype(str)
                .str.replace(' bytes', '', regex=False)
                .astype(float)
            )
            media_cipher = group['Ciphertext_size'].mean()
        else:
            media_cipher = nan

        media_tiempo = group['time'].mean()

        # Android-specific
        if 'Android' in str(device_type):
            # Strip units
            for col in ['Avg_RAM', 'Peak_RAM', 'App_Avg_RAM', 'App_Peak_RAM']:
                if col in group.columns:
                    group[col] = group[col].astype(str).str.replace(' MB', '', regex=False).astype(float)

            # CPU time
            if 'CPU_time' in group.columns:
                group['CPU_time'] = group['CPU_time'].astype(str).str.replace(' ms', '', regex=False).astype(float)

            media_ram = group['Avg_RAM'].mean()
            min_ram = group['Avg_RAM'].min()
            max_ram = group['Peak_RAM'].max()
            instance_ram = group['App_Avg_RAM'].mean()
            instance_min_ram = group['App_Avg_RAM'].min()
            instance_max_ram = group['App_Peak_RAM'].max()
            cpu_time = group['CPU_time'].mean() if 'CPU_time' in group.columns else nan
            min_cpu_time = group['CPU_time'].min() if 'CPU_time' in group.columns else nan
            max_cpu_time = group['CPU_time'].max() if 'CPU_time' in group.columns else nan

            results.loc[len(results)] = [
                device_type, name, media_tiempo, media_ram, min_ram, max_ram,
                None, None, None,
                instance_ram, None, instance_min_ram, instance_max_ram, None, None,
                cpu_time, min_cpu_time, max_cpu_time, media_cipher
            ]

        # WS / Python-specific
        else:
            # Clean CPU columns
            for col in ['Avg_CPU', 'Peak_CPU', 'Avg_instance_CPU', 'Peak_instance_CPU']:
                if col in group.columns:
                    # Extract only the first numeric value (ignore GHz, cores, etc.)
                    group[col] = (
                        group[col]
                        .astype(str)
                        .str.extract(r'([\d.]+)')   # get only the first number
                        .replace('N/A', nan)
                        .astype(float)
                    )

            # Clean RAM columns
            for col in ['Avg_RAM', 'Peak_RAM', 'Avg_instance_RAM', 'Peak_instance_RAM']:
                if col in group.columns:
                    group[col] = (
                        group[col]
                        .astype(str)
                        .str.extract(r'([\d.]+)')  # extract first number
                        .replace('N/A', nan)
                        .astype(float)
                    )

            media_ram = group['Avg_RAM'].mean()
            min_ram = group['Avg_RAM'].min()
            max_ram = group['Peak_RAM'].max()
            instance_ram = group['Avg_instance_RAM'].mean()
            instance_min_ram = group['Avg_instance_RAM'].min()
            instance_max_ram = group['Peak_instance_RAM'].max()
            instance_cpu = group['Avg_instance_CPU'].mean()
            instance_min_cpu = group['Avg_instance_CPU'].min()
            instance_max_cpu = group['Peak_instance_CPU'].max()
            media_cpu = group['Avg_CPU'].mean()
            min_cpu = group['Avg_CPU'].min()
            max_cpu = group['Peak_CPU'].max()

            results.loc[len(results)] = [
                device_type, name, media_tiempo, media_ram, min_ram, max_ram,
                media_cpu, min_cpu, max_cpu,
                instance_ram, instance_cpu, instance_min_ram, instance_max_ram,
                instance_min_cpu, instance_max_cpu,
                None, None, None, media_cipher
            ]


    # Para guardar los gráficos y los resultados
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    with open(os.path.join(folder_path, 'results.txt'), 'a') as f:
        f.write(f'Tiempo total: {tiempo_total}\n')

    # Guardamos los resultados en un archivo de texto en la carpeta de resultados
    for index, row in results.iterrows():
        print(row)
        with open(os.path.join(folder_path, 'results.txt'), 'a') as f:  # a porque se va a añadir
            f.write(str(row) + '\n')

    cmap = plt.get_cmap('tab20')  # Mapa de colores para las barras
    # Iterar sobre las columnas del DataFrame de resultados
    for i, column in enumerate(results.columns):
        if column not in results.columns or results[column].dropna().empty:
            continue

        if column not in ['activity_code', 'device_type']:
            filtered_results = results.dropna(subset=[column]).copy()
            if filtered_results.empty:
                continue

            # --- Extract normalized scheme names ---
            filtered_results['scheme_name'] = filtered_results['activity_code'].apply(
                lambda x: get_cs_label(str(x[0]) if isinstance(x, tuple) else str(x))
            )

            # --- Ensure consistent device names ---
            filtered_results['device_type'] = filtered_results['device_type'].astype(str).fillna('Unknown')

            # --- Iterate over each device type separately ---
            for device_type, df_device in filtered_results.groupby('device_type'):
                if df_device.empty:
                    continue

                # Sort by scheme for clean visuals
                df_device = df_device.sort_values('scheme_name')

                # Create label and color scheme
                plt.figure(figsize=(14, max(6, len(df_device) * 0.5)))
                cmap = plt.get_cmap('tab20')
                colors = [cmap(i) for i in np.linspace(0, 1, len(df_device))]

                # Plot one bar per algorithm (only for this device)
                plt.barh(df_device['scheme_name'], df_device[column], color=colors)

                # --- Axis labeling ---
                xlabel = ''
                if column == 'media_tiempo':
                    xlabel = 'Tiempo medio - Segundos'
                elif 'ram' in column:
                    xlabel = 'Consumo de RAM - MB'
                elif 'cpu' in column:
                    xlabel = 'Uso de CPU - %'
                elif column == 'Ciphertext_size':
                    xlabel = 'Tamaño de cifrado - bytes'
                if column in ['cpu_time', 'min_cpu_time', 'max_cpu_time']:
                    xlabel = 'Tiempo medio de CPU - ms'

                plt.xlabel(xlabel)
                plt.ylabel('Algoritmo')
                plt.title(f"{column.replace('_', ' ').upper()} - {device_type}")

                # Annotate values without overlap
                for j, (value, label) in enumerate(zip(df_device[column], df_device['scheme_name'])):
                    plt.text(value * 1.01, j, str(round(value, 3)), va='center', fontsize=9)

                plt.tight_layout()
                plt.subplots_adjust(right=0.9)
                output_file = f"{column.replace('_', '')}_{device_type}_plot.png"
                plt.savefig(os.path.join(folder_path, output_file), bbox_inches='tight')
                plt.close()

    # Crear una figura y ejes para el gráfico
    fig, axs = plt.subplots(7, 1, figsize=(20, 30))

    # Definir una función para extraer el valor numérico de la cadena con unidades
    def extract_numeric_value(text):
        text = str(text)
        match = re.search(r'[\d.]+', text)
        if match:
            return float(match.group())
        return None

    # Iterar sobre cada grupo de actividad
    for name, group in grouped:
        print(f"Procesando grupo: {name}")
        timestamps = group['timestamp']
        time_taken = group['time']
        ram_usage = group['Avg_RAM']
        cpu_usage = group['Avg_CPU'] if 'Avg_CPU' in group else None
        instance_ram_usage = group['Avg_instance_RAM'] if 'Avg_instance_RAM' in group else None
        instance_cpu_usage = group['Avg_instance_CPU'] if 'Avg_instance_CPU' in group else None
        app_avg_ram = group['App_Avg_RAM'] if 'App_Avg_RAM' in group else None
        app_cpu_time = group['CPU_time'] if 'CPU_time' in group else None

        # Convertir los timestamps a minutos desde el inicio
        min_timestamp = df_activities['timestamp'].min()
        tiempo_en_minutos = (timestamps - min_timestamp).dt.total_seconds() / 60

        # Extraer los valores numéricos sin ordenar
        time_taken_values = time_taken.apply(extract_numeric_value)
        ram_usage_values = ram_usage.apply(extract_numeric_value)
        cpu_usage_values = cpu_usage.apply(extract_numeric_value) if cpu_usage is not None else None
        instance_ram_usage_values = instance_ram_usage.apply(
            extract_numeric_value) if instance_ram_usage is not None else None
        instance_cpu_usage_values = instance_cpu_usage.apply(
            extract_numeric_value) if instance_cpu_usage is not None else None
        app_avg_ram_values = app_avg_ram.apply(extract_numeric_value) if app_avg_ram is not None else None
        app_cpu_time_values = app_cpu_time.apply(extract_numeric_value) if app_cpu_time is not None else None

        # Obtener la etiqueta de la leyenda
        if isinstance(name, tuple):
            scheme_or_activity, device = name
            label = f"{get_cs_label(str(scheme_or_activity))} ({device})"
        else:
            label = get_label(name)

        # Dibujar los gráficos como diagramas de puntos
        axs[0].scatter(tiempo_en_minutos, time_taken_values, label=label)
        axs[0].set_title('Tiempo de Ejecución - Unidades en segundos')

        axs[1].scatter(tiempo_en_minutos, ram_usage_values, label=label)
        axs[1].set_title('Consumo de RAM (Promedio, Android y WS - Unidades en MB)')
        axs[1].yaxis.set_major_locator(ticker.MaxNLocator(nbins=10))

        if cpu_usage_values is not None:
            axs[2].scatter(tiempo_en_minutos, cpu_usage_values, label=label)
            axs[2].set_title('Uso de CPU (Promedio, WS - Unidades en % de uso)')
            axs[2].yaxis.set_major_locator(ticker.MaxNLocator(nbins=10))

        if app_cpu_time_values is not None:
            axs[3].scatter(tiempo_en_minutos, app_cpu_time_values, label=label)
            axs[3].set_title('Tiempo de CPU de las actividades (Promedio, Android) - Unidades en ms')
            axs[3].yaxis.set_major_locator(ticker.MaxNLocator(nbins=10))

        if app_avg_ram_values is not None:
            axs[4].scatter(tiempo_en_minutos, app_avg_ram_values, label=label)
            axs[4].set_title('Consumo de RAM de la aplicación (Promedio, Android) - Unidades en MB')
            axs[4].yaxis.set_major_locator(ticker.MaxNLocator(nbins=10))

        if instance_cpu_usage_values is not None:
            axs[5].scatter(tiempo_en_minutos, instance_cpu_usage_values, label=label)
            axs[5].set_title('Uso de CPU de la instancia (Promedio, WS) - Unidades en % de uso')
            axs[5].yaxis.set_major_locator(ticker.MaxNLocator(nbins=10))

        if instance_ram_usage_values is not None:
            axs[6].scatter(tiempo_en_minutos, instance_ram_usage_values, label=label)
            axs[6].set_title('Consumo de RAM de la instancia (Promedio, WS) - Unidades en MB')
            axs[6].yaxis.set_major_locator(ticker.MaxNLocator(nbins=10))

    # Añadir etiquetas a los ejes y leyendas
    for ax in axs:
        ax.set_xlabel('Marca de tiempo de la actividad desde el inicio de la prueba (Minutos)')
        if 'RAM' in ax.get_title():
            ax.set_ylabel('RAM - MB')
        elif 'Tiempo de CPU' in ax.get_title():
            ax.set_ylabel('Tiempo - ms')
        elif 'CPU' in ax.get_title():
            ax.set_ylabel('CPU - %')
        elif 'Tiempo de Ejecución' in ax.get_title():
            ax.set_ylabel('Tiempo - Segundos')
        ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')

    # Guardar la figura
    plt.tight_layout()
    plt.savefig(os.path.join(folder_path, 'activity_plots.png'))
    plt.close()


if __name__ == '__main__':
    # analyze_activities('dj-domain-2048-mac-s21.json', 'Experiments/Variable Keylengths/')
    # Directorio base
    base_dir = 'Experiments'

    # Recorrer recursivamente el directorio base
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            # Comprobar que es un archivo JSON
            if not file.endswith('.json'):
                print(f'Archivo {file} no es un archivo JSON, se omitirá.')
                continue
            folder = root + '/'
            print('##############################################')
            print(f'Analizando archivo: {file} de la carpeta: {folder}')
            analyze_activities(file, folder)
