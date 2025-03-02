import json
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import Levenshtein as lev
import os
from tqdm import tqdm


# 相似度计算函数保持不变
def cos_similarity(text1, text2):
    vectorizer = TfidfVectorizer(stop_words='english')
    tfidf_matrix = vectorizer.fit_transform([text1, text2])
    return cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]


def lev_similarity(text1, text2):
    distance = lev.distance(text1, text2)
    max_length = max(len(text1), len(text2))
    if max_length == 0:
        return 1.0
    similarity_score = 1 - distance / max_length
    return similarity_score


def longest_common_substring(A, B):
    m, n = len(A), len(B)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    longest_length = 0
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if A[i - 1] == B[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
                longest_length = max(longest_length, dp[i][j])
    return longest_length


def lcs_similarity(A, B):
    L = longest_common_substring(A, B)
    m, n = len(A), len(B)
    if m + n == 0:
        return 1.0 if L == 0 else 0.0
    return (2 * L) / (m + n)


def sco_similarity(text1, text2):
    vectorizer = CountVectorizer().fit_transform([text1, text2])
    vectors = vectorizer.toarray()
    return cosine_similarity(vectors)[0][1]


# 主处理函数
def process_libraries(threshold, method, libraries_str, packages_file_path):
    threshold = float(threshold)
    # 检查文件是否存在
    if not os.path.isfile(packages_file_path):
        raise FileNotFoundError(f"找不到文件: {packages_file_path}")

    # 读取文件内容
    with open(packages_file_path, 'r', encoding='utf-8') as f:
        file_content = f.read()

    # 尝试将文件内容解析为Python对象
    try:
        packages = json.loads(file_content)  # 直接解析JSON字符串
        if isinstance(packages, str):
            packages = json.loads(packages)  # 直接解析JSON字符串
    except json.JSONDecodeError as e:
        raise ValueError(f"无法解析JSON文件: {packages_file_path}. 错误: {e}")

    # 打印调试信息
    print(
        f"Packages type: {type(packages)}, Packages content: {packages[:2] if isinstance(packages, list) else packages}")  # 显示前两个元素用于调试

    # 确认 packages 是一个列表
    if not isinstance(packages, list):
        raise ValueError(f"Expected a list of packages, but got {type(packages)}")

    package_names = [pkg['name'] for pkg in packages]

    # 分割输入的库名字符串
    libraries = libraries_str.split(';')

    # 方法映射字典
    methods = {
        'cos': cos_similarity,
        'lev': lev_similarity,
        'lcs': lcs_similarity,
        'sco': sco_similarity,
    }

    # 获取所选方法，默认值为 None
    similarity_function = methods.get(method)
    if not similarity_function:
        raise ValueError("未定义的相似度计算方法")

    # 只处理前两个元素
    libraries = libraries[:2]

    a = ['', '', '']
    b = ['', '', '']

    for i, library in enumerate(tqdm(libraries, desc="Processing libraries")):  # 使用tqdm添加进度条
        matches = [(pkg_name, similarity_function(library, pkg_name)) for pkg_name in package_names]
        matches = [match for match in matches if match[1] >= threshold]
        matches.sort(key=lambda x: -x[1])  # 根据相似度排序

        # 获取相似度最高的前三个
        top_matches = [match[0] for match in matches[:3]]
        # 如果不足三个，用空字符串填充
        top_matches += [''] * (3 - len(top_matches))

        # 将结果分别保存为a和b
        if i == 0:
            a = top_matches
        else:
            b = top_matches

    # 组织最终结果：只取第一个和第二个元素的第一个值，然后是第一个元素的第二个值
    new_predicts = [a[0], b[0], a[1]]

    # 去重（保留顺序）
    seen = set()
    new_predicts = [x for x in new_predicts if not (x in seen or seen.add(x))]

    # 补齐到3个元素
    while len(new_predicts) < 3:
        new_predicts.append('')

    # 返回结果，使用';'分割
    return ';'.join(new_predicts)


# 示例调用
if __name__ == "__main__":
    threshold = 0.2
    method = 'lev'
    libraries_str = "com.google.api-client:google-api-client;com.google.inject.extensions:guice-testlib;extra.lib"
    packages_file_path = '/Users/mac/Desktop/kulin/VulLibGen/white_list/label_desc.json'  # 替换为你的实际文件路径

    try:
        output = process_libraries(threshold, method, libraries_str, packages_file_path)
        print(output)
    except Exception as e:
        print(f"发生错误: {e}")