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
    name_low = name.lower()
    # PSI-CA schemes
    if "paillier" in name_low:
        return "Paillier"
    elif "damgardjurik" in name_low or "damg\u00e5rd" in name_low:
        # Match "DamgardJurik" (with or without accent)
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
    elif name_low == "csidh":
        return "CSIDH"
    elif name_low == "x25519" or name_low == "curve25519":
        # X25519 is an ECDH scheme on Curve25519
        return "X25519"
    elif name_low == "p256" or name_low == "p-256":
        # P-256 is an ECDH scheme on NIST curve P-256
        return "P-256"
    elif "kyber" in name_low:
        # Covers any variant named "Kyber"
        return "Kyber"
    elif "classicmceliece" in name_low or "classic-mceliece" in name_low:
        return "Classic McEliece"
    elif "frodo" in name_low:
        # FrodoKEM (Frodo) schemes
        return "FrodoKEM"
    elif name_low == "ntru":
        return "NTRU"
    elif name_low == "bike":
        return "BIKE"
    elif name_low == "hqc":
        return "HQC"
    elif "hybrid" in name_low and "kyber" in name_low and "x25519" in name_low:
        # Hybrid Kyber + X25519 scheme
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

        # Iterar sobre cada identificador en los datos
        for identificador in data['logs']:
            if 'activities' in data['logs'][identificador]:
                # Extraer las actividades para el identificador actual
                activities = data['logs'][identificador]['activities']

                # Convertir las actividades en un DataFrame
                df = pd.json_normalize(activities.values())

                # Agregar una columna para el identificador actual
                df['id'] = identificador

                # Convertir la columna de timestamp a datetime
                df['timestamp'] = pd.to_datetime(df['timestamp'], format="%d/%m/%Y %H:%M:%S", errors='coerce')
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
    tiempo_total = df_activities['timestamp'].max() - df_activities['timestamp'].min()
    print(f'Tiempo total: {tiempo_total}')

    # Ordena el DataFrame por el timestamp
    df_activities = df_activities.sort_values('timestamp')

    # Agrupa los datos por el código de actividad
    grouped = df_activities.groupby('activity_code')

    # Crea un DataFrame para almacenar los resultados
    results = pd.DataFrame(
        columns=['device_type', 'activity_code', 'media_tiempo', 'media_ram', 'min_ram', 'max_ram', 'media_cpu',
                 'min_cpu', 'max_cpu', 'instance_ram', 'instance_cpu', 'instance_min_ram', 'instance_max_ram',
                 'instance_min_cpu', 'instance_max_cpu', 'cpu_time', 'min_cpu_time', 'max_cpu_time', 'Ciphertext_size'])

    # Calcula las medias y los picos para cada grupo
    for name, group in grouped:
        # Comunes
        media_tiempo = group['time'].mean()
        # Quitar bytes de la columna de tamaño de cifrado y comprobar si existe
        if 'Ciphertext_size' in group:
            group['Ciphertext_size'] = group['Ciphertext_size'].str.replace(' bytes', '').astype(float)
            media_cipher = group['Ciphertext_size'].mean()

        # El valor device_type vendrá en Details o type porque no se unificó el nombre antes de algunas pruebas
        if 'Details' in group and group['Details'].iloc[0] is not nan:
            device_type = group['Details'].iloc[0]
        else:
            device_type = group['type'].iloc[0]

        # Específicos Android
        if 'Android' in device_type:
            # Elimina "MB" de las columnas de RAM y convierte a números
            group['Avg_RAM'] = group['Avg_RAM'].str.replace(' MB', '').astype(float)
            group['Peak_RAM'] = group['Peak_RAM'].str.replace(' MB', '').astype(float)
            media_ram = group['Avg_RAM'].mean()
            group['App_Avg_RAM'] = group['App_Avg_RAM'].str.replace(' MB', '').astype(float)
            group['App_Peak_RAM'] = group['App_Peak_RAM'].str.replace(' MB', '').astype(float)
            min_ram = group['Avg_RAM'].min()
            max_ram = group['Peak_RAM'].max()
            instance_ram = group['App_Avg_RAM'].mean()
            instance_min_ram = group['App_Avg_RAM'].min()
            instance_max_ram = group['App_Peak_RAM'].max()
            group['CPU_time'] = group['CPU_time'].str.replace(' ms', '').astype(float)
            cpu_time = group['CPU_time'].mean()
            min_cpu_time = group['CPU_time'].min()
            max_cpu_time = group['CPU_time'].max()

        # Específicos Python
        else:
            # Filtrar los valores de CPU que son 0% o N/A
            group = group.query(
                "`Avg_CPU` != '0%' & `Avg_CPU` != 'N/A' & `Peak_CPU` != '0%' & `Peak_instance_CPU` != '0%'")
            group['Avg_CPU'] = group['Avg_CPU'].fillna('').astype(str).str.split(' ').str[0]
            group['Avg_CPU'] = group['Avg_CPU'].str.replace('%', '').astype(float)
            group['Peak_CPU'] = group['Peak_CPU'].str.replace('%', '').astype(float)
            group['Avg_instance_RAM'] = group['Avg_instance_RAM'].str.replace(' MB', '').astype(float)
            group['Peak_instance_RAM'] = group['Peak_instance_RAM'].str.replace(' MB', '').astype(float)
            group['Avg_instance_CPU'] = group['Avg_instance_CPU'].str.replace('%', '').astype(float)
            group['Peak_instance_CPU'] = group['Peak_instance_CPU'].str.replace('%', '').astype(float)
            # La Avg_RAM viene como 11956.39 MB / 32679.41 MB - 36.59%, hay que coger solo el primer valor y quitando MB
            group['Avg_RAM'] = group['Avg_RAM'].fillna('').astype(str).str.split(' ').str[0]
            group['Avg_RAM'] = pd.to_numeric(group['Avg_RAM'], errors='coerce')
            group['Peak_RAM'] = group['Peak_RAM'].fillna('').astype(str).str.replace(' MB', '').astype(float)
            group['Peak_RAM'] = pd.to_numeric(group['Peak_RAM'],
                                              errors='coerce')  # Para que no de error si no es numérico
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

        # Añade los resultados al DataFrame
        if 'Android' not in device_type:
            results.loc[len(results)] = [device_type, name, media_tiempo, media_ram, min_ram, max_ram, media_cpu,
                                         min_cpu,
                                         max_cpu,
                                         instance_ram, instance_cpu, instance_min_ram, instance_max_ram,
                                         instance_min_cpu,
                                         instance_max_cpu, None, None, None, media_cipher if 'Ciphertext_size'
                                                                                             in group else None]
        else:
            results.loc[len(results)] = [device_type, name, media_tiempo, media_ram, min_ram, max_ram, None, None, None,
                                         instance_ram, None, instance_min_ram, instance_max_ram, None,
                                         None, cpu_time, min_cpu_time, max_cpu_time, media_cipher if 'Ciphertext_size'
                                                                                                     in group else None]

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
        if column != 'activity_code' and column != 'device_type':
            # Filtrar NaN antes de nada, para poder seguir teniendo gráficas de los que tengamos datos
            filtered_results = results.dropna(subset=[column]).copy()
            # Aplicar el get_label para que los gráficos tengan un título más descriptivo
            filtered_results['activity_name'] = filtered_results['activity_code'].apply(get_label)

            if not filtered_results.empty:  # Verificar que haya datos después de filtrar NaN
                # Crear el gráfico
                plt.figure(figsize=(15, 5))  # Ajustar tamaño del gráfico
                # Crear una lista de colores basada en los códigos de actividad
                colors = [cmap(i) for i in np.linspace(0, 1, len(filtered_results['activity_code'].unique()))]
                plt.barh(filtered_results['activity_name'], filtered_results[column], color=colors)
                xlabel = ''
                if column == 'media_tiempo':
                    xlabel = 'Tiempo medio - Segundos'
                elif column.__contains__('ram'):
                    xlabel = 'Consumo de RAM - MB'
                elif column.__contains__('cpu'):
                    xlabel = 'Uso de CPU - %'
                elif column == 'Ciphertext_size':
                    xlabel = 'Tamaño de cifrado - bytes'
                if column == 'cpu_time' or column == 'min_cpu_time' or column == 'max_cpu_time':
                    xlabel = 'Tiempo medio de CPU - ms'
                plt.xlabel(xlabel)
                plt.ylabel('Actividad')
                # Concatenar en el título ambos tipos de dispositivos, cada uno representa una barra distinta
                device_types = filtered_results['device_type'].unique()  # Get unique device types
                plt.title(column.replace('_', ' ').upper() + ' - Dispositivos: ' + ' - '.join(device_types))

                # Mostrar los resultados al lado de la barra
                for i, value in enumerate(filtered_results[column]):
                    plt.text(value, i, str(round(value, 3)))

                plt.tight_layout()
                # Guardar el gráfico
                plt.savefig(os.path.join(folder_path, column.replace('_', '') + '_plot.png'))
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
