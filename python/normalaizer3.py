import pandas as pd
import math
from collections import Counter
import os
import json
from datetime import datetime

# --- Функции остаются без изменений ---
def shannon_entropy(s):
    s = str(s)
    if not s: return 0
    counts = Counter(s)
    return -sum((count/len(s)) * math.log2(count/len(s)) for count in counts.values())

def classify_path(cmd):
    cmd = str(cmd).lower()
    if not cmd: return 4
    if "temp" in cmd: return 1
    if "system32" in cmd: return 2
    if "program files" in cmd: return 3
    return 4

def prepare_process_sequence(events):
    sequence = []
    if not events: return sequence
    
    def parse_dt(ts_str):
        try: return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").timestamp()
        except: return 0

    prev_time = parse_dt(events[0]['metrics'].get('Time', '2026-06-20 00:00:00'))
    
    for e in events:
        metrics = e.get('metrics', {})
        statics = e.get('statics', {})
        curr_time = parse_dt(metrics.get('Time', '2026-06-20 00:00:00'))
        delta_time = curr_time - prev_time
        
        features = {
            "event_id": int(statics.get('EventId', 0)),
            "delta_time": delta_time,
            "cpu_usage": metrics.get('CpuUsage', 0),
            "handle_count": metrics.get('HandleCount', 0),
            "thread_count": metrics.get('ThreadCount', 0),
            "working_set": metrics.get('WorkingSetSize', 0),
            "private_bytes": metrics.get('PrivatePageCount', 0),
            "page_faults": metrics.get('PageFaultCount', 0),
            "context_switches": metrics.get('ContextSwitches', 0),
            "ent_cmd": shannon_entropy(statics.get('Image', '')),
            "path_cat": classify_path(statics.get('Image', '')),
            "copy": e.get('copy', 0)
        }
        sequence.append(features)
        prev_time = curr_time
    return sequence

# --- Новая логика обработки ---

def process_case_folder(source_dir, output_dir):
    """Обрабатывает одну конкретную папку с логами"""
    os.makedirs(output_dir, exist_ok=True)
    master_log = []
    process_counter = 0
    
    # Ищем файлы events.json внутри этой папки
    for root, dirs, files in os.walk(source_dir):
        if "events.json" in files:
            file_path = os.path.join(root, "events.json")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    events = json.load(f)
                
                if not events: continue
                process_counter += 1
                
                statics = events[0].get("statics", {})
                guid = statics.get("ProcessGuid", "unknown").strip("{}")
                full_image = statics.get("Image", "unknown")
                proc_name = os.path.basename(full_image).lower().replace('.exe', '')
                
                filename = f"{proc_name}_{guid}_{process_counter}.csv"
                save_path = os.path.join(output_dir, filename)
                
                proc_features = prepare_process_sequence(events)
                pd.DataFrame(proc_features).to_csv(save_path, index=False)
                master_log.extend(proc_features)
                    
            except Exception as e:
                print(f"  Ошибка в {file_path}: {e}")
    
    if master_log:
        pd.DataFrame(master_log).to_csv(os.path.join(output_dir, "master_chronology.csv"), index=False)
    return process_counter

def main():
    root_input_folder = input("Введите путь к родительской папке с наборами данных: ").strip()
    if not os.path.exists(root_input_folder):
        print("Путь не найден.")
        return

    # 1. Создаем общую папку для всех результатов
    base_output_dir = "normalized_data"
    os.makedirs(base_output_dir, exist_ok=True)

    # 2. Генерируем уникальное имя для текущего запуска
    folder_base_name = os.path.basename(os.path.normpath(root_input_folder))
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_run_name = f"normalized_{folder_base_name}_{timestamp_str}"
    
    # 3. Объединяем пути: normalized_data/normalized_имя_дата
    output_root = os.path.join(base_output_dir, unique_run_name)
    os.makedirs(output_root, exist_ok=True)
    
    print(f"Начинаю обработку. Результаты будут в: {output_root}")

    # Перебираем все подпапки в указанном пути
    for item in os.listdir(root_input_folder):
        item_path = os.path.join(root_input_folder, item)
        
        if os.path.isdir(item_path):
            print(f"Обработка папки: {item}")
            # Создаем подпапку внутри папки текущего запуска
            case_output_dir = os.path.join(output_root, item)
            
            count = process_case_folder(item_path, case_output_dir)
            print(f"  -> Готово. Обработано процессов: {count}")

if __name__ == "__main__":
    main()