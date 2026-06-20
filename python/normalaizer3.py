import pandas as pd
import math
from collections import Counter
import os
import json
from datetime import datetime

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

    # Берем время из первого события
    prev_time = parse_dt(events[0]['metrics'].get('Time', '2026-06-20 00:00:00'))
    
    for e in events:
        metrics = e.get('metrics', {})
        statics = e.get('statics', {})
        
        curr_time = parse_dt(metrics.get('Time', '2026-06-20 00:00:00'))
        delta_time = curr_time - prev_time
        
        features = {
            "event_id": int(statics.get('EventId', 0)),
            "delta_time": delta_time,
            
            # Метрики из вашего JSON
            "cpu_usage": metrics.get('CpuUsage', 0),
            "handle_count": metrics.get('HandleCount', 0),
            "thread_count": metrics.get('ThreadCount', 0),
            "working_set": metrics.get('WorkingSetSize', 0),
            "private_bytes": metrics.get('PrivatePageCount', 0),
            "page_faults": metrics.get('PageFaultCount', 0),
            "context_switches": metrics.get('ContextSwitches', 0),
            
            # Статика
            "ent_cmd": shannon_entropy(statics.get('Image', '')),
            "path_cat": classify_path(statics.get('Image', '')),
            
            "copy": e.get('copy', 0)
        }
        
        sequence.append(features)
        prev_time = curr_time
        
    return sequence

def main():
    root_folder = input("Введите путь к папке с логами: ").strip()
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    output_base_dir = os.path.join("processed_nn_data", f"run_{timestamp_str}")
    os.makedirs(output_base_dir, exist_ok=True)
    
    master_log = []
    process_counter = 0

    for root, dirs, files in os.walk(root_folder):
        if "events.json" in files:
            file_path = os.path.join(root, "events.json")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    events = json.load(f)
                
                if not events: continue
                process_counter += 1
                
                # Имя и GUID из структуры statics
                statics = events[0].get("statics", {})
                full_image = statics.get("Image", "unknown")
                proc_name = os.path.basename(full_image).lower().replace('.exe', '')
                guid = statics.get("ProcessGuid", "unknown").strip("{}")[:8]
                
                filename = f"{proc_name}_{guid}_{process_counter}.csv"
                save_path = os.path.join(output_base_dir, filename)
                
                proc_features = prepare_process_sequence(events)
                pd.DataFrame(proc_features).to_csv(save_path, index=False)
                
                master_log.extend(proc_features)
                    
            except Exception as e:
                print(f"Ошибка в {file_path}: {e}")

    if master_log:
        pd.DataFrame(master_log).to_csv(os.path.join(output_base_dir, "master_chronology.csv"), index=False)
        print(f"Готово! Обработано процессов: {process_counter}")

if __name__ == "__main__":
    main()