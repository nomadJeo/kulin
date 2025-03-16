import os

from parase.pom_parse import llm_communicate

system_prompt = """Generate technical descriptions in English for C programming dependencies following these rules:
1. For each dependency in format 'library-name' or 'header-file' (e.g. openssl, zlib, stdio.h)
2. Describe core functionality and typical use cases in systems programming
3. Include key features and compatible versions where applicable
4. Use concise technical language (80-120 words)
5. Output JSON array format:
[{
    "name": "dependency identifier",
    "description": "generated text"
},...]

Example:
[{
    "name": "openssl",
    "description": "A robust, full-featured open-source toolkit implementing the SSL/TLS protocols and general-purpose cryptography library. Widely used for secure network communication..."
},{
    "name": "zlib",
    "description": "A lossless data compression library implementing the DEFLATE algorithm. Commonly used for file compression/decompression and network data optimization..."
}]"""

def collect_dependencies(project_path):
    dependencies = []

    # 递归遍历目录树
    for root, dirs, files in os.walk(project_path):
        # 检查当前目录是否包含kulin.txt
        if 'kulin.txt' in files:
            file_path = os.path.join(root, 'kulin.txt')
            try:
                # 读取文件内容
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        # 去除首尾空白并过滤空行
                        cleaned_line = line.strip()
                        if cleaned_line:
                            dependencies.append(cleaned_line)
            except Exception as e:
                print(f"读取文件 {file_path} 时出错: {str(e)}")

    # 使用集合去重并保持原始顺序
    seen = set()
    unique_dependencies = [x for x in dependencies if not (x in seen or seen.add(x))]

    return llm_communicate(unique_dependencies,system_prompt,10)


# 使用示例
if __name__ == "__main__":
    # 输入参数设置
    project_path= input("请输入项目文件夹路径: ").strip()

    if not os.path.isdir(project_path):
        print("错误：输入的项目路径不存在或不是目录")
    else:
        collect_dependencies(project_path)