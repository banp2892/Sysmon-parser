import json
import re
import os
from collections import defaultdict

def parse_line(line):
    try:
        obj = json.loads(line)
        xml = obj.get("data", "")
        # Извлекаем GUIDы
        guid_match = re.search(r"ProcessGuid['\"]?>\{([^}]+)\}", xml, re.IGNORECASE)
        parent_guid_match = re.search(r"ParentProcessGuid['\"]?>\{([^}]+)\}", xml, re.IGNORECASE)
        
        guid = guid_match.group(1).lower() if guid_match else None
        parent_guid = parent_guid_match.group(1).lower() if parent_guid_match else None
        
        if not guid: return None
            
        return {
            "guid": guid,
            "parent_guid": parent_guid,
            "event_id": re.search(r'<EventID>(\d+)</EventID>', xml).group(1) if re.search(r'<EventID>(\d+)</EventID>', xml) else "0",
            "metrics": obj.get("metrics", {}),
            "timestamp": obj.get("timestamp", 0),
            "name": get_clean_name(xml)
        }
    except: return None

def get_clean_name(xml):
    image_match = re.search(r"Image'>([^<]+)</Data>", xml)
    return os.path.basename(image_match.group(1)) if image_match else "unknown"

def create_folder_structure(guid, tree, current_path):
    info = tree[guid]
    safe_name = re.sub(r'[\\/*?:"<>|]', "", info['name'])
    folder_name = f"{safe_name}_{guid[:8]}"
    path = os.path.join(current_path, folder_name)
    os.makedirs(path, exist_ok=True)
    
    with open(os.path.join(path, "events.json"), 'w', encoding='utf-8') as f:
        json.dump(info["events"], f, indent=4)
        
    for child_guid in tree[guid]["children"]:
        create_folder_structure(child_guid, tree, path)

def export_graph_to_file(tree, roots, output_path):
    """Создает визуализацию связей для анализатора/нейросети."""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("--- PROCESS HIERARCHY GRAPH ---\n")
        def write_node(guid, indent=0):
            info = tree[guid]
            prefix = "  " * indent
            f.write(f"{prefix}{info['name']}_{guid[:8]} (Events: {len(info['events'])})\n")
            for child in info["children"]:
                write_node(child, indent + 1)
        
        for root in roots:
            write_node(root)
    print(f"Граф визуализации записан в: {output_path}")

def main():
    path = input("Путь до файла: ").strip().replace('"', '')
    if not os.path.exists(path): return

    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    processes = {}
    for line in lines:
        data = parse_line(line)
        if not data: continue
        
        guid = data["guid"]
        if guid not in processes:
            processes[guid] = {"events": [], "name": data["name"], "parent_guid": data["parent_guid"], "children": []}
        
        # Дедупликация событий внутри процесса
        if not processes[guid]["events"] or (processes[guid]["events"][-1]["event_id"] != data["event_id"]):
            processes[guid]["events"].append(data)

    # Строим дерево
    tree = processes
    roots = []
    for guid, info in tree.items():
        p_guid = info["parent_guid"]
        if p_guid and p_guid in tree:
            tree[p_guid]["children"].append(guid)
        else:
            roots.append(guid)

    print(f"Найдено корневых процессов: {len(roots)}")
    
    # 1. Запись папок
    root_dir = os.path.splitext(os.path.basename(path))[0] + "_tree"
    for root_guid in roots:
        create_folder_structure(root_guid, tree, root_dir)
    
    # 2. Запись файла визуализации
    export_graph_to_file(tree, roots, os.path.join(root_dir, "process_tree_graph.txt"))
    
    print(f"Готово! Результат в папке: {root_dir}")

if __name__ == "__main__":
    main()