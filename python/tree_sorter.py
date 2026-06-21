import json
import re
import os

def parse_line(line):
    try:
        data = json.loads(line)
        event_root = data.get("Event", {})
        if not event_root: return None
        
        static = event_root.get("static_field", {})
        metrics = event_root.get("metrics", {})
        
        guid = static.get("ProcessGuid", "").strip("{}").lower()
        parent_guid = static.get("ParentProcessGuid", "").strip("{}").lower()
        if not guid: return None
        
        return {
            "guid": guid,
            "parent_guid": parent_guid,
            "static": static,
            "metrics": metrics
        }
    except Exception:
        return None

def are_metrics_identical(m1, m2):
    """
    Явное сравнение полей. Мы руками берем каждый показатель из словаря.
    """
    # Список полей для сравнения
    fields = [
        "ContextSwitches", "CpuUsage", "HandleCount",
        "NonPagedPoolUsage", "PageFaultCount", "PagedPoolUsage",
        "ParentPid", "PrivatePageCount", "SessionId", "ThreadCount",
        "VirtualSize", "WorkingSetSize"
    ]
    
    for field in fields:
        val1 = m1.get(field)
        val2 = m2.get(field)
        
        if val1 is None or val2 is None:
            return False
            
        if abs(float(val1) - float(val2)) > 0.0001:
            return False
            
    return True

def create_folder_structure(guid, tree, current_path):
    info = tree[guid]
    img = info["statics"].get("Image", "unknown")
    safe_name = re.sub(r'[\\/*?:"<>|]', "", os.path.basename(img))
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
        def write_node(guid, indent=0):
            info = tree[guid]
            name = os.path.basename(info["statics"].get("Image", "unknown"))
            prefix = "  " * indent
            f.write(f"{prefix}|- {name}_{guid[:12]} | Events: {len(info['events'])}\n")
            for child in info["children"]:
                write_node(child, indent + 1)
        for root in roots:
            write_node(root)

def main():
    path = input("Путь до файла: ").strip().replace('"', '')
    if not os.path.exists(path): return

    processes = {}
    total_lines = 0
    duplicate_count = 0

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            total_lines += 1
            data = parse_line(line)
            if not data: continue
            
            guid = data["guid"]
            if guid not in processes:
                processes[guid] = {
                    "statics": {}, 
                    "events": [], 
                    "children": [], 
                    "parent_guid": data["parent_guid"]
                }
            
            for k, v in data["static"].items():
                if v and (k not in processes[guid]["statics"] or not processes[guid]["statics"][k]):
                    processes[guid]["statics"][k] = v

            if processes[guid]["events"]:
                last_metrics = processes[guid]["events"][-1]["metrics"]
                if are_metrics_identical(data["metrics"], last_metrics):
                    processes[guid]["events"][-1]["copy"] += 1
                    duplicate_count += 1
                    continue
            
            new_event = {
                "statics": processes[guid]["statics"],
                "metrics": data["metrics"],
                "copy": 0
            }
            processes[guid]["events"].append(new_event)

    print(f"\n--- СТАТИСТИКА ---")
    print(f"Всего обработано строк: {total_lines}")
    print(f"Дубликатов удалено: {duplicate_count}")
    print(f"Уникальных событий сохранено: {total_lines - duplicate_count}")

    roots = []
    for guid, info in processes.items():
        p_guid = info["parent_guid"]
        if p_guid and p_guid in processes:
            processes[p_guid]["children"].append(guid)
        else:
            roots.append(guid)

    root_dir = os.path.splitext(os.path.basename(path))[0] + "_tree"
    if roots:
        os.makedirs(root_dir, exist_ok=True)
        for root_guid in roots:
            create_folder_structure(root_guid, processes, root_dir)
        export_graph_to_file(processes, roots, os.path.join(root_dir, "process_tree_graph.txt"))
        print(f"Готово! Результаты в папке: {root_dir}")

if __name__ == "__main__":
    main()