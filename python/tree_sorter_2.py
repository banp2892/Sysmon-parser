import json
import re
import os
from collections import defaultdict

def parse_line(line):
    try:
        obj = json.loads(line)
        
        # 1. Извлекаем данные из переданных блоков
        # Если в JSON уже есть готовые блоки, используем их, иначе — берем из корня
        p_info = obj.get("process_info", obj) # fallback на случай если поля в корне
        parent_info = obj.get("parent_info", obj)
        metrics = obj.get("metrics", obj)
        
        # XML данные для GUID (все еще нужны для связи процессов)
        xml = obj.get("data", "")
        guid_match = re.search(r"ProcessGuid['\"]?>\{([^}]+)\}", xml, re.IGNORECASE)
        parent_guid_match = re.search(r"ParentProcessGuid['\"]?>\{([^}]+)\}", xml, re.IGNORECASE)
        
        guid = guid_match.group(1).lower() if guid_match else obj.get("guid")
        parent_guid = parent_guid_match.group(1).lower() if parent_guid_match else obj.get("parent_guid")
        
        if not guid: return None
        
        return {
            "guid": guid,
            "parent_guid": parent_guid,
            "event_id": str(obj.get("event_id", re.search(r'<EventID>(\d+)</EventID>', xml).group(1) if re.search(r'<EventID>(\d+)</EventID>', xml) else "0")),
            "timestamp": obj.get("timestamp", 0),
            
            # Разделение по блокам
            "process_info": {
                "name": get_clean_name(xml) if get_clean_name(xml) != "unknown" else p_info.get("name", "unknown"),
                "company": p_info.get("company", "unknown"),
                "cmd": p_info.get("command_line", p_info.get("cmd", "")),
                "isSigned": p_info.get("is_signed", False)
            },
            "metrics": metrics,
            "parent_info": {
                "pid": parent_info.get("parent_pid", parent_info.get("pid", 0)),
                "name": parent_info.get("name", "unknown"),
                "cmd": parent_info.get("command_line", ""), # Добавляем cmd родителя
                "integrity": parent_info.get("integrity_level", 0),
                "elevated": parent_info.get("is_elevated", False),
                "start_time": parent_info.get("parent_start_time", 0),
                "is_service": parent_info.get("is_service", False),
                "isSigned": parent_info.get("is_signed", False)
            }
        }
    except Exception as e:
        return None

def get_clean_name(xml):
    image_match = re.search(r"Image'>([^<]+)</Data>", xml)
    return os.path.basename(image_match.group(1)) if image_match else "unknown"

def get_reliable_name(info):
    name = info['process_info'].get('name', 'unknown')
    if name != "unknown" and name != "":
        return name
    # Попытка достать имя из командной строки, если name не задан
    cmd = info['process_info'].get('cmd', '')
    if cmd:
        # Берем первый аргумент из кавычек или до первого пробела
        match = re.search(r'"([^"]+)"|([^\s]+)', cmd)
        if match:
            path = match.group(1) or match.group(2)
            return os.path.basename(path)
    return "unknown"

def create_folder_structure(guid, tree, current_path):
    info = tree[guid]
    safe_name = re.sub(r'[\\/*?:"<>|]', "", info['process_info']['name'])
    # Убрали [:8], теперь имя папки содержит полный GUID
    folder_name = f"{safe_name}_{guid}"
    path = os.path.join(current_path, folder_name)
    os.makedirs(path, exist_ok=True)
    
    with open(os.path.join(path, "events.json"), 'w', encoding='utf-8') as f:
        json.dump(info["events"], f, indent=4)
        
    for child_guid in tree[guid]["children"]:
        create_folder_structure(child_guid, tree, path)

def export_graph_to_file(tree, roots, output_path):
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("--- PROCESS HIERARCHY SUMMARY ---\n\n")
        
        # Вспомогательная функция для подсчета всей ветки
        def get_stats(guid):
            info = tree[guid]
            total_events = len(info["events"])
            total_children = 0
            total_dupes = info.get("duplicates", 0) # Считаем дубликаты в ветке
            
            for child in info["children"]:
                child_events, child_count, child_dupes = get_stats(child)
                total_events += child_events
                total_children += (1 + child_count)
                total_dupes += child_dupes
            return total_events, total_children, total_dupes

        def write_node(guid, indent=0):
            info = tree[guid]
            prefix = "  " * indent
            
            name = get_reliable_name(info)
            total_events, total_children, total_dupes = get_stats(guid)
            sec = info.get("parent_security", {})
            
            # Проверяем, есть ли хотя бы одно событие с аномалией в списке events этого процесса
            is_anomaly = any(ev.get("anomaly") == "SUSPICIOUS_SERVICE_ACTIVITY" for ev in info["events"])
            anomaly_tag = " [!!! АНОМАЛИЯ]" if is_anomaly else ""
            service_tag = " [SVC]" if sec.get("is_service") else ""
            # ------------------------
            
            is_admin = " [ADMIN]" if sec.get("elevated") else " [USER]"
            integrity = sec.get("integrity", 0)
            
            stats_str = f"Events: {len(info['events'])} (local), {total_dupes} ignored, {total_children} children"
            
            # Добавляем теги в строку вывода
            f.write(f"{prefix}|- {name}_{guid[:12]}{service_tag}{anomaly_tag} {is_admin} (Int: {integrity}) | {stats_str}\n")
            
            for child in info["children"]:
                write_node(child, indent + 1)
        
        for root in roots:
            write_node(root)
    print(f"Подробный отчет записан в: {output_path}")

def main():
    path = input("Путь до файла: ").strip().replace('"', '')
    if not os.path.exists(path): return

    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    processes = {}
    total_lines = len(lines)
    duplicate_count = 0  # Счётчик удаленных дубликатов

    for line in lines:
            data = parse_line(line)
            if not data: 
                continue
            




            guid = data["guid"]
            p_guid = data["parent_guid"]
            data["anomaly"] = None
            if guid not in processes:
                processes[guid] = {
                    "events": [], 
                    "process_info": data["process_info"],
                    "parent_guid": data["parent_guid"],
                    "parent_security": data["parent_info"],
                    "children": [],
                    "duplicates": 0,
                    # Инициализируем ключи для сравнения
                    "last_event_signature": None,
                    "current_copy_count": 0 
                }
                processes[guid]["last_event_obj"] = None
            

            if p_guid in processes:
                parent = processes[p_guid]
                # Допустим, событие создания дочернего процесса имеет временную метку
                child_time = data["timestamp"]
                parent_start = data["parent_info"].get("start_time", 0)
                
                # Если служба запустила процесс менее чем через 5 секунд после своего старта
                if data["parent_info"].get("is_service") and (0 < child_time - parent_start < 5):
                    data["anomaly"] = "SUSPICIOUS_SERVICE_ACTIVITY"


            event_signature = (data["event_id"], json.dumps(data["process_info"], sort_keys=True))

            if processes[guid]["last_event_signature"] == event_signature:
                # Обновляем счетчик дубликатов для уже сохраненного объекта
                processes[guid]["last_event_obj"]["copy"] += 1
                processes[guid]["duplicates"] += 1
                duplicate_count += 1
            else:
                # Это новое уникальное событие
                data["copy"] = 0 # Сбрасываем в 0 при создании
                processes[guid]["last_event_signature"] = event_signature
                processes[guid]["last_event_obj"] = data # Запоминаем ссылку
                processes[guid]["events"].append(data)


    # Вывод статистики в консоль
    print(f"\n--- СТАТИСТИКА ---")
    print(f"Всего обработано строк: {total_lines}")
    print(f"Дубликатов удалено: {duplicate_count}")
    print(f"Уникальных событий сохранено: {total_lines - duplicate_count}")

    tree = processes
    roots = []
    for guid, info in tree.items():
        p_guid = info["parent_guid"]
        if p_guid and p_guid in tree:
            tree[p_guid]["children"].append(guid)
        else:
            roots.append(guid)

    root_dir = os.path.splitext(os.path.basename(path))[0] + "_tree"
    # Создаем папку, если вдруг roots пустой
    if roots:
        os.makedirs(root_dir, exist_ok=True)
        for root_guid in roots:
            create_folder_structure(root_guid, tree, root_dir)
        
        export_graph_to_file(tree, roots, os.path.join(root_dir, "process_tree_graph.txt"))
        print(f"Готово! Результаты в папке: {root_dir}")
    else:
        print("Ошибка: Корневые процессы не найдены.")

if __name__ == "__main__":
    main()