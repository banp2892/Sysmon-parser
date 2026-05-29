import json
import xml.dom.minidom
import os

def prettify_xml(xml_string):
    try:
        dom = xml.dom.minidom.parseString(xml_string)
        return dom.toprettyxml(indent="  ")
    except Exception as e:
        return f""

def main():
    file_path = input("Введите полный путь к файлу логов: ").strip().replace('"', '')
    
    if not os.path.exists(file_path):
        print(f"Ошибка: Файл '{file_path}' не найден.")
        return

    # Получаем директорию исходного файла и его чистое имя
    directory = os.path.dirname(file_path)
    filename = os.path.basename(file_path)
    
    # Создаем имя для выходного файла (например: readable_sysmon_log_...xml)
    output_filename = os.path.join(directory, "readable_" + filename.replace(".jsonl", ".xml"))

    print(f"Обработка файла: {filename}...")
    
    count = 0
    with open(file_path, 'r', encoding='utf-8') as f_in, \
         open(output_filename, 'w', encoding='utf-8') as f_out:
        
        f_out.write("<Root>\n")
        
        for line in f_in:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                raw_xml = data.get("data", "")
                metrics = data.get("metrics", {}) # Получаем словарь метрик
                
                if raw_xml:
                    # Пишем XML-событие
                    dom = xml.dom.minidom.parseString(raw_xml)
                    f_out.write(dom.documentElement.toprettyxml(indent="  "))
                    
                    # Пишем наши дополнительные метрики сразу после него
                    f_out.write("  <EnrichedMetrics>\n")
                    for key, value in metrics.items():
                        if isinstance(value, dict): # Для вложенных данных типа IO
                            f_out.write(f"    <{key}>\n")
                            for sub_k, sub_v in value.items():
                                f_out.write(f"      <{sub_k}>{sub_v}</{sub_k}>\n")
                            f_out.write(f"    </{key}>\n")
                        else:
                            f_out.write(f"    <{key}>{value}</{key}>\n")
                    f_out.write("  </EnrichedMetrics>\n")
                    
                    count += 1
            except Exception as e:
                print(f"Ошибка парсинга строки: {e}")
                continue
        
        f_out.write("</Root>")

    print(f"Готово! Обработано событий: {count}")
    print(f"Результат сохранен в: {output_filename}")

if __name__ == "__main__":
    main()