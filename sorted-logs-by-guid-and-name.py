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
    try:
        obj = json.loads(line)
        xml = obj.get("data", "")
        
        # Универсальный поиск: ищем и двойные, и одинарные кавычки
        # Используем re.IGNORECASE для надежности
        guid_match = re.search(r"ProcessGuid['\"]?>\{([^}]+)\}", xml, re.IGNORECASE)
        
        # Ищем EventID независимо от тега
        eid_match = re.search(r'<EventID>(\d+)</EventID>', xml)
        
        guid = guid_match.group(1) if guid_match else None
        
        # Если GUID все еще None, выведем отладочную информацию
        if not guid:
            print(f"Внимание: Не удалось найти GUID в строке: {xml[:100]}...")
            return None
            
        return {
            "guid": guid,
            "event_id": eid_match.group(1) if eid_match else "0",
            "metrics": obj.get("metrics", {}),
            "timestamp": obj.get("timestamp", 0)
        }
    except Exception as e:
        return None

def get_clean_name(xml):
    """Извлекает имя исполняемого файла из пути."""
    image_match = re.search(r"Image'>([^<]+)</Data>", xml)
    if image_match:
        full_path = image_match.group(1)
        # Берем только последнюю часть пути (имя файла)
        return os.path.basename(full_path)
    return "unknown_process"

def main():
    print("Введите путь до файла:")
    path_to_file = input().strip().replace('"', '')

    lines = ReadJsonData(path_to_file)
    if not lines: return

    # Создаем папку для результатов
    folder_name = os.path.splitext(os.path.basename(path_to_file))[0] + "_processed"
    os.makedirs(folder_name, exist_ok=True)

    # Группируем по GUID
    processes = defaultdict(lambda: {"events": [], "name": "unknown"})
    for line in lines:
        data = parse_line(line)
        if data:
            xml = json.loads(line).get("data", "")
            proc_name = get_clean_name(xml)
            processes[data["guid"]]["events"].append(data)
            processes[data["guid"]]["name"] = proc_name

    # Сохраняем каждый процесс в отдельный файл
    for guid, info in processes.items():
        events = info["events"]
        events.sort(key=lambda x: x["timestamp"])
        
        # 1. Очищаем имя процесса от запрещенных символов
        safe_name = re.sub(r'[\\/*?:"<>|]', "", info["name"])
        
        # 2. Создаем подпапку для этого процесса
        process_dir = os.path.join(folder_name, safe_name)
        os.makedirs(process_dir, exist_ok=True)
        
        # 3. Путь к файлу теперь внутри подпапки
        filename = f"{guid}.json"
        output_path = os.path.join(process_dir, filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=4)
            
    print(f"Готово! Данные структурированы в папке: {folder_name}")

if __name__ == "__main__":
    main()