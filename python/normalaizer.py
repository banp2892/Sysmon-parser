import pandas as pd
import numpy as np
import math
from collections import Counter
import os
import json
from datetime import datetime

def shannon_entropy(s):
    if not s: return 0
    counts = Counter(s)
    return -sum((count/len(s)) * math.log2(count/len(s)) for count in counts.values())

def classify_path(cmd):
    # Упрощенная классификация папок
    if "temp" in cmd.lower(): return 1
    if "system32" in cmd.lower(): return 2
    if "program files" in cmd.lower(): return 3
    return 4

def prepare_process_sequence(events):
    sequence = []
    
    prev_time = events[0]['timestamp']
    prev_io = events[0].get('metrics', {}).get('io', {})
    prev_io_read = prev_io.get('read_bytes', 0)
    prev_io_write = prev_io.get('write_bytes', 0)
    
    for i, e in enumerate(events):
        # Вычисляем дельты
        delta_time = e['timestamp'] - prev_time
        io = e.get('metrics', {}).get('io', {})
        curr_read = io.get('read_bytes', 0)
        curr_write = io.get('write_bytes', 0)
        
        delta_read = curr_read - prev_io_read if i > 0 else 0
        delta_write = curr_write - prev_io_write if i > 0 else 0
        
        # Вектор признаков БЕЗ идентификаторов и имен
        features = {
            # Признаки времени и событий
            "event_id": int(e['event_id']),
            "delta_time": delta_time,
            
            # Признаки активности (IO + CPU)
            "delta_read": max(0, delta_read),
            "delta_write": max(0, delta_write),
            "cpu_slice": e.get('metrics', {}).get('cpu_slice', 0),
            "raw_cpu": e.get('metrics', {}).get('_raw_cpu', 0),
            
            # Признаки нагрузки на систему
            "handle_count": e.get('metrics', {}).get('handle_count', 0),
            "private_bytes": e.get('metrics', {}).get('private_bytes', 0),
            "thread_count": e.get('metrics', {}).get('thread_count', 0),
            
            # Признаки поведения командной строки (энтропия, а не сам текст!)
            "ent_cmd": shannon_entropy(e.get('process_info', {}).get('cmd', '')),
            "ent_p_cmd": shannon_entropy(e.get('parent_info', {}).get('cmd', '')),
            "path_cat": classify_path(e.get('process_info', {}).get('cmd', '')),
            
            # Контекст запуска (бинарные флаги)
            "p_integrity": e.get('parent_info', {}).get('integrity', 0),
            "p_elevated": 1 if e.get('parent_info', {}).get('elevated') else 0,
            "anomaly": 1 if e.get('anomaly') else 0,
            "copy": e.get('copy', 0)
        }
        
        sequence.append(features)
        
        prev_time = e['timestamp']
        prev_io_read = curr_read
        prev_io_write = curr_write
        
    return sequence




def main():
    root_folder = input("Введите путь к папке с логами: ").strip()
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # --- ЛОГИКА ОПРЕДЕЛЕНИЯ КОРНЕВОГО ПРОЦЕССА ---
    root_info = {"name": "root", "guid": "0000"}
    found_root = False
    
    for root, dirs, files in os.walk(root_folder):
        if "events.json" in files:
            try:
                with open(os.path.join(root, "events.json"), 'r', encoding='utf-8') as f:
                    events = json.load(f)
                
                # Ищем процесс, у которого нет родителя (или GUID родителя пустой)
                statics = events[0].get("statics", {})
                p_guid = statics.get("ParentProcessGuid", "")
                
                if not p_guid or p_guid == "00000000-0000-0000-0000-000000000000":
                    full_image = statics.get("Image", "root.exe")
                    root_info["name"] = os.path.basename(full_image).lower().replace('.exe', '')
                    root_info["guid"] = statics.get("ProcessGuid", "0000").strip("{}")[:8]
                    found_root = True
                    break
            except: continue
    
    # Создаем итоговую папку: Корневой_GUID_Время
    folder_name = f"{root_info['name']}_{root_info['guid']}_{timestamp_str}"
    output_base_dir = os.path.join("processed_nn_data", folder_name)
    os.makedirs(output_base_dir, exist_ok=True)
    print(f"Результаты будут сохранены в: {output_base_dir}")
    
    master_log = []
    process_counter = 0

    # Обработка всех процессов
    for root, dirs, files in os.walk(root_folder):
        if "events.json" in files:
            file_path = os.path.join(root, "events.json")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    events = json.load(f)
                
                if not events: continue
                process_counter += 1
                
                # Берем GUID из текущего процесса для имени файла
                statics = events[0].get("statics", {})
                guid = statics.get("ProcessGuid", "unknown").strip("{}")[:8]
                full_image = statics.get("Image", "unknown")
                proc_name = os.path.basename(full_image).lower().replace('.exe', '')
                
                filename = f"{proc_name}_{guid}_{process_counter}.csv"
                save_path = os.path.join(output_base_dir, filename)
                
                # Обработка дельт
                proc_features = prepare_process_sequence(events)
                pd.DataFrame(proc_features).to_csv(save_path, index=False)
                
                master_log.extend(proc_features)
                    
            except Exception as e:
                print(f"Ошибка в {file_path}: {e}")

    # Создание мастер-файла
    if master_log:
        pd.DataFrame(master_log).to_csv(os.path.join(output_base_dir, "master_chronology.csv"), index=False)
        print(f"Готово! Обработано процессов: {process_counter}")

if __name__ == "__main__":
    main()