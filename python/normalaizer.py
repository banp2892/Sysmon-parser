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
    # УБРАЛИ: events = sorted(events, key=lambda x: x['timestamp'])
    sequence = []
    
    # Чтобы дельта считалась корректно, нам нужно знать состояние на начало
    # Инициализируем первым событием
    prev_time = events[0]['timestamp']
    prev_io_read = events[0].get('metrics', {}).get('io', {}).get('read_bytes', 0)
    prev_io_write = events[0].get('metrics', {}).get('io', {}).get('write_bytes', 0)
    
    for i, e in enumerate(events):
        # 1. Время между событиями
        delta_time = e['timestamp'] - prev_time
        
        # 2. Дельта байт (считаем разницу с предыдущим, если это не первое событие)
        io = e.get('metrics', {}).get('io', {})
        current_read = io.get('read_bytes', 0)
        current_write = io.get('write_bytes', 0)
        
        delta_read = current_read - prev_io_read if i > 0 else 0
        delta_write = current_write - prev_io_write if i > 0 else 0
        
        # 3. Энтропия и классификация (оставляем как есть)
        ent_cmd = shannon_entropy(e['process_info'].get('cmd', ''))
        ent_p_cmd = shannon_entropy(e['parent_info'].get('cmd', ''))
        path_cat = classify_path(e['process_info'].get('cmd', ''))
        
        features = {
            "timestamp": e['timestamp'],
            "event_id": int(e['event_id']),
            "delta_time": delta_time,
            "delta_read": max(0, delta_read),
            "delta_write": max(0, delta_write),
            "cpu_slice": e['metrics'].get('cpu_slice', 0),
            "ent_cmd": ent_cmd,
            "ent_p_cmd": ent_p_cmd,
            "path_cat": path_cat
        }
        
        sequence.append(features)
        
        # Обновляем для след. итерации
        prev_time = e['timestamp']
        prev_io_read = current_read
        prev_io_write = current_write
        
    return sequence




def main():
    root_folder = input("Введите путь к папке с логами: ").strip()
    
    # Генерируем уникальное имя для папки запуска: КорневойПроцесс_GUID_Время
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Сначала найдем корневой процесс для названия папки
    root_info = {"name": "root", "guid": "0000"}
    for root, dirs, files in os.walk(root_folder):
        if "events.json" in files:
            with open(os.path.join(root, "events.json"), 'r', encoding='utf-8') as f:
                events = json.load(f)
            
            if events and events[0].get("parent_guid") is None:
                folder_name = os.path.basename(root)
                parts = folder_name.split('_', 1)
                
                # Присваиваем имя и GUID
                root_info["name"] = parts[0].replace(".exe", "")
                root_info["guid"] = parts[1] if len(parts) > 1 else "root"
                break
    
    # Создаем итоговую папку: Корневой_GUID_Время
    folder_name = f"{root_info['name']}_{root_info['guid']}_{timestamp_str}"
    output_base_dir = os.path.join("processed_nn_data", folder_name)
    os.makedirs(output_base_dir, exist_ok=True)
    print(f"Результаты будут сохранены в: {output_base_dir}")
    
    master_log = []
    process_counter = 0

    # Обработка
    for root, dirs, files in os.walk(root_folder):
        if "events.json" in files:
            file_path = os.path.join(root, "events.json")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    events = json.load(f)
                
                if not events: continue
                
                process_counter += 1
                folder_base_name = os.path.basename(root)
                parts = folder_base_name.split('_', 1)
                
                # Если частей 2, то guid — это вторая часть, иначе — имя папки
                guid = parts[1] if len(parts) > 1 else "unknown"
                
                # Имя процесса берем из JSON, как вы и делали
                full_name = events[0].get("process_info", {}).get("name", "unknown").lower()
                proc_name = full_name[:-4] if full_name.endswith('.exe') else full_name
                
                # Имя файла теперь будет гарантированно уникальным
                filename = f"{proc_name}_{guid}_{process_counter}.csv"
                save_path = os.path.join(output_base_dir, filename)
                
                # Обработка
                proc_features = prepare_process_sequence(events)
                pd.DataFrame(proc_features).to_csv(save_path, index=False)
                
                # Добавление в мастер-лог
                for item in proc_features:
                    item['process_name'] = proc_name
                    item['guid'] = guid
                    master_log.append(item)
                    
            except Exception as e:
                print(f"Ошибка в {file_path}: {e}")

    # Создание мастер-файла
    if master_log:
        pd.DataFrame(master_log).to_csv(os.path.join(output_base_dir, "master_chronology.csv"), index=False)
        print(f"Готово! Обработано процессов: {process_counter}")

if __name__ == "__main__":
    main()
