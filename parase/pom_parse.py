import json
import os
import time
import xml.etree.ElementTree as ET

from llm.llm import QwenClient


# 批量处理提示词模板
system_prompt = """Generate technical descriptions in English for Maven dependencies following these rules:
1. For each dependency in format 'groupId:artifactId:version'
2. Describe main functionality and typical use cases
3. Use concise technical language (80-120 words)
4. Output JSON array format:
[{
    "name": "full dependency name",
    "description": "generated text"
},...]

Example:
[{
    "name": "org.springframework.boot:spring-boot-starter-web:2.7.0",
    "description": "Provides essential components for building web applications with Spring Boot..."
}]"""

def parse_pom_file(pom_path):
    """解析本地pom.xml文件并提取依赖信息"""
    try:
        # 读取文件内容
        with open(pom_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()

        # 解析XML内容
        root = ET.fromstring(xml_content)
        dependencies = []
        ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}

        # 处理依赖项
        for element in root.findall('.//maven:dependency', ns):
            group_id = element.findtext('maven:groupId', namespaces=ns) or ""
            artifact_id = element.findtext('maven:artifactId', namespaces=ns) or ""
            version = element.findtext('maven:version', namespaces=ns) or ""

            if version:  # 仅记录有版本号的条目
                dependencies.append(f"{group_id}:{artifact_id}:{version}")

        # 处理插件项
        for plugin in root.findall('.//maven:plugin', ns):
            group_id = plugin.findtext('maven:groupId', namespaces=ns) or ""
            artifact_id = plugin.findtext('maven:artifactId', namespaces=ns) or ""
            version = plugin.findtext('maven:version', namespaces=ns) or ""

            if version:
                dependencies.append(f"{group_id}:{artifact_id}:{version}")

        return dependencies

    except ET.ParseError as e:
        print(f"XML解析错误 ({pom_path}): {str(e)}")
        return []
    except Exception as e:
        print(f"处理文件失败 ({pom_path}): {str(e)}")
        return []

def find_pom_files(root_dir):
    """递归查找所有pom.xml文件"""
    pom_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.lower() == 'pom.xml':
                pom_files.append(os.path.join(dirpath, filename))
    return pom_files

def process_projects(project_folder):
    pom_files = find_pom_files(project_folder)
    if not pom_files:
        print(f"No pom.xml files found in {project_folder}")
        return

    unique_dependencies = set()
    for pom_path in pom_files:
        dependencies = parse_pom_file(pom_path)
        unique_dependencies.update(dependencies)

    return llm_communicate(unique_dependencies,system_prompt,10)

def llm_communicate(unique_dependencies,system_prompt,batch_size = 10):

    # 初始化客户端
    qwen_client = QwenClient(model_name="qwen-max")
    all_deps = list(unique_dependencies)
    total = len(all_deps)

    result = []

    for i in range(0, total, batch_size):
        batch = all_deps[i:i + batch_size]
        try:
            # 构造批量请求
            user_content = "Dependencies:\n" + "\n".join(batch)

            response = qwen_client.Think([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ])

            # 新增：解析响应内容
            try:
                parsed_response = json.loads(response)
                if isinstance(parsed_response, list):
                    result.extend(parsed_response)
                else:
                    print(f"Invalid response format in batch {i // batch_size}")
            except json.JSONDecodeError as e:
                print(f"JSON parsing failed in batch {i // batch_size}: {str(e)}")

        except Exception as e:
            print(f"Batch {i // batch_size} failed: {str(e)}")

        time.sleep(1)  # 控制请求频率

        # 返回合并后的JSON格式结果
    return json.dumps(result, indent=2)

if __name__ == "__main__":
    # 输入参数设置
    project_folder = input("请输入项目文件夹路径: ").strip()

    if not os.path.isdir(project_folder):
        print("错误：输入的项目路径不存在或不是目录")
    else:
        process_projects(project_folder)
