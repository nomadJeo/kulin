import json
from tqdm import tqdm


def format_shots(shots):
    """将列表格式化为所需的字符串形式"""
    formatted_shots = [f"The affected package is {shot}" if not shot.startswith("maven:") else shot for shot in shots]
    return " and ".join(formatted_shots)


def query(vuln, k, shot_key):
    shots = [lib['lib_name'] for lib in vuln[shot_key][:k]]
    desc_escaped = vuln["desc"].replace("\"", "\\\"").replace("\n", " ")  # 提前处理双引号和换行符
    formatted_shots = format_shots(shots)  # 格式化shots列表
    prompt = (
        f'Below is a C/C++ vulnerability description. Please identify the software name affected by it. '
        f'Input: {desc_escaped}. Top {k} search result is {formatted_shots}. '
        'What is affected packages?'
    )
    return prompt.strip()


def raw_query(vuln, shot_key):
    desc_escaped = vuln["desc"].replace("\"", "\\\"").replace("\n", " ")  # 提前处理双引号和换行符
    prompt = (
        f'Below is a C/C++ vulnerability description. Please identify the software name affected by it. '
        f'Input: {desc_escaped}. '
        'What is affected packages?'
    )
    return prompt.strip()


def prepare_prompts_c(train):
    """
    准备提示并返回JSON格式的数据

    :param train: 输入的训练数据集，JSON格式
    :return: 处理后的提示集合，JSON格式
    """
    vulns = train  # 使用传入的train数据
    all_prompts = []

    for k in [1]:  # 如果需要更多的k值，可以扩展这个列表
        for vuln in tqdm(vulns, desc=f"Preparing prompts for k={k}"):
            rerank_prompt = query(vuln, k, 'rerank_k') if k > 0 else raw_query(vuln, 'rerank_k')
            all_prompts.append({
                "instruction": "",
                "input": rerank_prompt,
                "output": vuln['labels']
            })

    return all_prompts


# 示例调用
if __name__ == "__main__":
    # 假设train是一个已经加载的JSON对象

    train = [{"cve_id": "CVE-2024-37288", "desc": "A deserialization issue in Kibana can lead to arbitrary code execution when Kibana attempts to parse a YAML document containing a crafted payload. This issue only affects users that use  Elastic Security’s built-in AI tools https://www.elastic.co/guide/en/security/current/ai-for-security.html  and have configured an  Amazon Bedrock connector https://www.elastic.co/guide/en/security/current/assistant-connect-to-bedrock.html .", "labels": [], "top_k": [], "rerank_k": [{"lib_name": "org.sonatype.security:security-rest", "re_rank_score": 0.0004154173075221479}, {"lib_name": "com.sksamuel.elastic4s:elastic4s-xpack-security_2.11", "re_rank_score": 0.00041513744508847594}, {"lib_name": "com.sksamuel.elastic4s:elastic4s-xpack-security_2.12", "re_rank_score": 0.0004151257744524628}, {"lib_name": "com.sksamuel.elastic4s:elastic4s", "re_rank_score": 0.0004151219909545034}, {"lib_name": "com.sksamuel.elastic4s:elastic4s-xpack-security_2.13", "re_rank_score": 0.00041511765448376536}, {"lib_name": "com.sksamuel.elastic4s:elastic4s_2.10", "re_rank_score": 0.00041509902803227305}, {"lib_name": "com.sksamuel.elastic4s:elastic4s_2.11", "re_rank_score": 0.0004150964959990233}, {"lib_name": "org.sonatype.security:security-parent", "re_rank_score": 0.0004150551394559443}, {"lib_name": "com.sandinh:elastic4s-xpack-security_2.12", "re_rank_score": 0.00041473633609712124}, {"lib_name": "pro.javatar.security:security-filter", "re_rank_score": 0.00041416543535888195}]}]

    all_prompts_json = prepare_prompts_c(train)

    # 打印结果或保存到文件
    print(json.dumps(all_prompts_json, indent=4, ensure_ascii=False))
