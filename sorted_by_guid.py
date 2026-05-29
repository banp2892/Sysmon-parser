import json
import re
import os
from collections import defaultdict

def ReadJsonData(path):
    """Считывает файл и возвращает список строк."""
    if not os.path.exists(path):
        print(f"Ошибка: Файл '{path}' не найден.")
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return f.readlines()

def parse_line(line):
    """Извлекает ProcessGuid, EventID и метрики из одной строки JSON."""
    try:
        obj = json.loads(line)
        xml = obj.get("data", "")
        
        # Регулярные выражения для извлечения данных из XML
        guid_match = re.search(r'ProcessGuid">\{([^}]+)\}', xml)
        eid_match = re.search(r'<EventID>(\d+)</EventID>', xml)
        
        return {
            "guid": guid_match.group(1) if guid_match else "unknown",
            "event_id": eid_match.group(1) if eid_match else "0",
            "metrics": obj.get("metrics", {}),
            "timestamp": obj.get("timestamp", 0)
        }
    except:
        return None

def main():
    print("Введите путь до файла:")
    path_to_file = input().strip().replace('"', '')

    lines = ReadJsonData(path_to_file)
    if not lines: return

    # Создаем папку для результатов
    folder_name = os.path.splitext(os.path.basename(path_to_file))[0] + "_processed"
    os.makedirs(folder_name, exist_ok=True)

    # Группируем по GUID
    processes = defaultdict(list)
    for line in lines:
        data = parse_line(line)
        if data:
            processes[data["guid"]].append(data)

    # Сохраняем каждый процесс в отдельный файл
    for guid, events in processes.items():
        # Сортируем события по времени
        events.sort(key=lambda x: x["timestamp"])
        
        output_path = os.path.join(folder_name, f"{guid}.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=4)
            
    print(f"Готово! Обработано {len(processes)} процессов. Файлы лежат в папке: {folder_name}")

if __name__ == "__main__":
    main()