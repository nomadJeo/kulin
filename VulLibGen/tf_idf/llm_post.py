import json
import Levenshtein

weights = (1, 2, 2)

def calculate_similarity(distance, length, weights=(1, 2, 2)):
    """
    根据Levenshtein距离和字符串长度计算相似度。
    相似度计算公式：(加权后的最大可能距离 - 加权后的实际距离) / 加权后的最大可能距离
    """
    max_possible_distance = length * max(weights)
    return (max_possible_distance - distance) / max_possible_distance


def closest_artifact(artifact_id, artifacts, similarityThreshold):
    if artifact_id in artifacts:
        return [artifact_id]

    similarityThreshold = float(similarityThreshold)

    matches = []
    for item in artifacts:
        distance = Levenshtein.distance(artifact_id, item.split(':')[-1], weights=weights)
        similarity = calculate_similarity(distance, len(artifact_id), weights)
        if similarity >= similarityThreshold:
            matches.append((similarity, item))

    # 按相似度排序并取前3个
    return [item for _, item in sorted(matches, reverse=True)[:3]]


def closest_group(group_id, groups, similarityThreshold):
    similarityThreshold = float(similarityThreshold)
    if len(groups) == 0:
        return [""]

    matches = []
    for item in groups:
        try:
            full_id = ':'.join(item.split(':')[-2:])  # 获取完整的groupId:artifactId
            distance = Levenshtein.distance(group_id, item.split(':')[-2], weights=weights)
            similarity = calculate_similarity(distance, len(group_id), weights)
            if similarity >= similarityThreshold:
                matches.append((similarity, full_id))  # 添加完整的id
        except IndexError:
            continue

    return [item for _, item in sorted(matches, reverse=True)[:3]]


def match_label(original_label, maven_path, similarityThreshold):
    similarityThreshold = float(similarityThreshold)
    with open(maven_path, 'r') as f:
        maven_corpus = json.load(f)

    if isinstance(maven_corpus, str):
        maven_corpus = json.loads(maven_corpus)

    lib_names = set([lib['name'] for lib in maven_corpus])

    artifacts = {':'.join(item.split(':')[-2:]): set() for item in lib_names}  # 使用完整的groupId:artifactId作为键
    for item in lib_names:
        artifacts[':'.join(item.split(':')[-2:])].add(item)

    matches = []
    if not original_label or not isinstance(original_label, str):
        return ';'.join(['', '', ''])  # 直接返回3个空字符串

    if original_label in lib_names:
        matches.append(original_label)  # 直接添加原始标签
    else:
        components = original_label.split(':')
        group_id, artifact_id = components[-2] if len(components) > 1 else "", components[-1]

        print(f"Searching for: {artifact_id}")

        if artifact_id in {k.split(':')[-1] for k in artifacts.keys()}:
            matched_items = closest_group(group_id, {k for k in artifacts.keys() if k.endswith(f":{artifact_id}")}, similarityThreshold)
            matches.extend(matched_items)
        else:
            advanced_artifacts = closest_artifact(artifact_id, {k.split(':')[-1] for k in artifacts.keys()}, similarityThreshold)
            for adv_artifact in advanced_artifacts:
                matched_groups = closest_group(group_id, {k for k in artifacts.keys() if k.endswith(f":{adv_artifact}")}, similarityThreshold)
                if matched_groups:  # 如果找到了匹配的group，则添加
                    matches.extend(matched_groups)
                else:  # 如果没有找到匹配的group，但artifact本身是一个很好的匹配，直接添加artifact
                    matches.append([k for k in artifacts.keys() if k.endswith(f":{adv_artifact}")][0])

    matched_labels = list(dict.fromkeys(matches))[:3]  # 去重并限制数量
    while len(matched_labels) < 3:
        matched_labels.append("")

    print(f"Final matches: {matched_labels}")

    return ';'.join(matched_labels)
# #示例使用
# original_label_example = "altrmi:altrmi-server-interface"
# maven_path_example = "/Users/mac/Desktop/kulin/VulLibGen/white_list/label_desc.json"
# similarityThreshold_example = "0.5"
#
# matched_label = match_label(original_label_example, maven_path_example, similarityThreshold_example)
# print(f"Matched label: {matched_label}")