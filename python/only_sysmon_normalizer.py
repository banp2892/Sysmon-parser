import pandas as pd
import os
import json
from datetime import datetime

def prepare_process_sequence(events):
    """
    Преобразует список событий в последовательность: {event_id, copy}.
    Теперь возвращает каждое событие в том порядке, в котором оно было.
    """
    if not events:
        return []

    sequence = []
    
    # Просто проходим по всем событиям и добавляем их в список
    for e in events:
        sequence.append({
            "event_id": int(e.get('event_id', 0)),
            "copy": int(e.get('copy', 0))
        })
    
    return sequence

def main():
    root_folder = input("Введите путь к папке с логами: ").strip()
    
    # Генерируем уникальное имя для папки запуска
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Поиск корневого процесса для названия папки
    root_info = {"name": "root", "guid": "0000"}
    for root, dirs, files in os.walk(root_folder):
        if "events.json" in files:
            with open(os.path.join(root, "events.json"), 'r', encoding='utf-8') as f:
                events = json.load(f)
            
            if events and events[0].get("parent_guid") is None:
                folder_name = os.path.basename(root)
                parts = folder_name.split('_', 1)
                root_info["name"] = parts[0].replace(".exe", "")
                root_info["guid"] = parts[1] if len(parts) > 1 else "root"
                break
    
    # Создаем итоговую папку
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
                guid = parts[1] if len(parts) > 1 else "unknown"
                
                full_name = events[0].get("process_info", {}).get("name", "unknown").lower()
                proc_name = full_name[:-4] if full_name.endswith('.exe') else full_name
                
                filename = f"{proc_name}_{guid}_{process_counter}.csv"
                save_path = os.path.join(output_base_dir, filename)
                
                # Получаем чистую последовательность
                proc_features = prepare_process_sequence(events)
                
                # Сохраняем индивидуальный CSV (теперь только event_id и copy)
                pd.DataFrame(proc_features).to_csv(save_path, index=False)
                
                # Добавление в мастер-лог
                for item in proc_features:
                    master_log.append(item)
                    
            except Exception as e:
                print(f"Ошибка в {file_path}: {e}")

    # Создание мастер-файла
    if master_log:
        pd.DataFrame(master_log).to_csv(os.path.join(output_base_dir, "master_chronology.csv"), index=False)
        print(f"Готово! Обработано процессов: {process_counter}")

if __name__ == "__main__":
    main()