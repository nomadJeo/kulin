import json


def normalize_scores(data):
    """
    对给定的数据中的're_rank_score'进行归一化处理。

    参数:
    data (list): 包含CVE信息和rerank_k列表的JSON数据。

    返回:
    list: 包含带有归一化分数的数据。
    """
    # 提取所有的re_rank_score
    scores = [item['re_rank_score'] for item in data[0]['rerank_k']]

    # 计算最小和最大的分数
    min_score = min(scores)
    max_score = max(scores)

    # 对每个分数进行归一化
    for item in data[0]['rerank_k']:
        original_score = item['re_rank_score']
        normalized_score = (original_score - min_score) / (max_score - min_score)
        item['normalized_re_rank_score'] = normalized_score

    return data


def main():
    # 示例JSON数据
    data = [{"cve_id": "CVE-2025-0108", "desc": "An authentication bypass in the Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to bypass the authentication otherwise required by the PAN-OS management web interface and invoke certain PHP scripts. While invoking these PHP scripts does not enable remote code execution, it can negatively impact integrity and confidentiality of PAN-OS.\n\nYou can greatly reduce the risk of this issue by restricting access to the management web interface to only trusted internal IP addresses according to our recommended  best practices deployment guidelines https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431 .\n\nThis issue does not affect Cloud NGFW or Prisma Access software.", "labels": [], "top_k": [], "rerank_k": [{"lib_name": "3proxy", "re_rank_score": 0.9801127910614014}, {"lib_name": "webserver", "re_rank_score": 0.9798234105110168}, {"lib_name": "php-radius", "re_rank_score": 0.32081496715545654}, {"lib_name": "suhosin", "re_rank_score": 0.2195557802915573}, {"lib_name": "mod_auth_mellon", "re_rank_score": 0.14650870859622955}, {"lib_name": "mac-telnet", "re_rank_score": 0.1157461628317833}, {"lib_name": "pam_p11", "re_rank_score": 0.06577834486961365}, {"lib_name": "optee_os", "re_rank_score": 0.06490012258291245}, {"lib_name": "php-src", "re_rank_score": 0.03533374145627022}, {"lib_name": "mongoose-os", "re_rank_score": 0.003319003153592348}]}]

    # 归一化处理
    normalized_data = normalize_scores(data)

    # 打印归一化后的数据
    print(json.dumps(normalized_data, indent=2))


if __name__ == "__main__":
    main()