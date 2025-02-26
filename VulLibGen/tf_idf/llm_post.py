import json
import pandas as pd
import Levenshtein

weights = (1, 2, 2)


def closest_artifact(artifact_id, artifacts):
    if artifact_id in artifacts:
        return [artifact_id]

    distances = [(Levenshtein.distance(artifact_id, item, weights=weights), item) for item in artifacts]
    # 返回前3个最小距离的项，如果存在的话
    return [item for _, item in sorted(distances)[:3]]


def closest_group(group_id, groups):
    if len(groups) == 0:
        return [group_id]
    if len(groups) == 1:
        return list(groups)

    distances = [(Levenshtein.distance(group_id, item.split(':')[-2], weights=weights), item) for item in groups]
    # 返回前3个最小距离的项，如果存在的话
    return [item for _, item in sorted(distances)[:3]]


def match_label(original_label, maven_path):
    """
    根据提供的 original_label 和 maven_path 匹配最接近的库名。

    参数:
    original_label (str): 原始标签字符串。
    maven_path (str): 包含 Maven 库信息的 JSON 文件路径。

    返回:
    str: 最接近的匹配库名，多个结果以分号分隔。
    """
    # 加载 Maven 库信息
    with open(maven_path, 'r') as f:
        maven_corpus = json.load(f)
    lib_names = set([lib['name'] for lib in maven_corpus])

    artifacts = {item.split(':')[-1]: set() for item in lib_names}
    for item in lib_names:
        components = item.split(':')
        artifacts[components[-1]].add(item)

    matches = []
    if not original_label or not isinstance(original_label, str):  # 检查是否为空或不是字符串
        return ''

    if original_label in lib_names:
        return original_label
    if len(original_label.split(':')) > 1:
        group_id, artifact_id = original_label.split(':')[-2], original_label.split(':')[-1]
    else:
        group_id, artifact_id = "", original_label.split(':')[-1]
    if artifact_id in artifacts:
        matches.extend(closest_group(group_id, artifacts[artifact_id]))
    else:
        advanced_artifacts = closest_artifact(artifact_id, artifacts)
        for adv_artifact in advanced_artifacts:
            matches.extend(closest_group(group_id, artifacts.get(adv_artifact, set())))
    # 去重并返回最多3个不重复的结果
    matched_labels = list(dict.fromkeys(matches))[:3]
    return ';'.join(matched_labels) if matched_labels else ''


# # 示例使用
# original_label_example = "org.elasticsearch.client:elasticsearch-rest-high-level-client"
# maven_path_example = "/path/to/maven/corpus.json"
#
# matched_label = match_label(original_label_example, maven_path_example)
# print(f"Matched label: {matched_label}")