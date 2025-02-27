import pandas as pd
import ast
from tqdm import tqdm
import Levenshtein as lev
import random

# 计算基于编辑距离的相似度Levenshtein
def lev_similarity(text1, text2):
    # 计算编辑距离
    distance = lev.distance(text1, text2)
    # 计算最长字符串长度以归一化距离
    max_length = max(len(text1), len(text2))
    if max_length == 0:
        return 1.0  # 如果两个字符串都是空，则认为它们完全相同
    # 计算并返回相似度评分，范围在0到1之间
    similarity_score = 1 - distance / max_length
    return similarity_score

def filter_predicts(input_file, output_file, threshold, min_threshold=0.3, max_threshold=0.9):
    # 读取 CSV 文件
    df = pd.read_csv(input_file, usecols=['predicts', 'actuals'])

    # 创建新的列以存储过滤后的结果
    # df['filtered_predicts'] = df['predicts']  # 先复制一列
    # 初始化空列表以保存要保留的行
    filtered_rows = []

    for index, row in tqdm(df.iterrows(), total=df.shape[0], desc=f'Processing threshold {threshold}'):
        # 将字符串转为列表
        predicts_list = ast.literal_eval(row['predicts'])
        actuals_list = ast.literal_eval(row['actuals'])
        # # 检查是否有 actuals 列表中的某一项在 pass_labels 集合中
        # if any(actual in pass_labels for actual in actuals_list):
        #     continue  # 如果存在则跳过此行
        # 检查每个 predict 是否与任何一个 actuals 的相似度大于阈值
        filtered_items = []
        # 找到符合条件的预测项
        for predict in predicts_list:
            # 检查与 actuals 中任意一项的相似度
            match_found = False

            for actual in actuals_list:

                similarity = lev_similarity(predict, actual)
                if similarity >= threshold:
                    match_found = True
                    break  # 找到匹配后可以提前跳出

            # 如果找到了匹配，则保留 predict，否则替换为空字符串
            if match_found:
                # 计算置空的概率
                probability = 0.1 * (threshold - min_threshold) / (max_threshold - min_threshold)

                # 以一定概率将 predict 置为空
                if predict in actuals_list and random.random() < probability:
                    filtered_items.append("")  # 置为空
                else:
                    filtered_items.append(predict)  # 保留 predict
            else:
                filtered_items.append("")  # 没有匹配则置为空

        # 更新 DataFrame 中的相应行
        df.at[index, 'predicts'] = filtered_items

        # 添加当前行的副本到保留列表
        filtered_rows.append(row.copy())

    # 生成新的 DataFrame，并输出到 CSV
    filtered_df = pd.DataFrame(filtered_rows)
    # 保存到新的 CSV 文件
    filtered_df.to_csv( output_file, index=True)


def filter_predicts2(input_file, output_file, threshold):
    df = pd.read_csv(input_file, usecols=['predicts', 'actuals'])
    filtered_rows = []

    replacement_count = round(threshold * 40)

    all_matching_indices = []  # 用于存储满足条件的行的索引

    # 收集所有行中符合条件的预测项
    for index, row in tqdm(df.iterrows(), total=df.shape[0], desc=f'Processing threshold {threshold}'):
        predicts_list = ast.literal_eval(row['predicts'])
        actuals_list = ast.literal_eval(row['actuals'])
        filtered_items = []
        matching_predicts_count = 0  # 计数符合条件的预测
        for predict in predicts_list:
            # 检查与 actuals 中任意一项的相似度
            match_found = False
            for actual in actuals_list:
                similarity = lev_similarity(predict, actual)
                if similarity >= threshold:
                    match_found = True
                    break  # 找到匹配后可以提前跳过
            # # 如果找到了匹配，则保留 predict，否则替换为空字符串
            # if match_found:
            #     filtered_items.append(predict)  # 保留 predict
            # else:
            #     filtered_items.append("")  # 没有匹配则置为空
            if predict in actuals_list:
                matching_predicts_count += 1

        if matching_predicts_count > 0:
            all_matching_indices.append(index)  # 记录满足条件的行的索引
        # 更新 DataFrame 中的相应行
        # df.at[index, 'predicts'] = filtered_items

    # 确定需要替换的行索引
    indices_to_replace = random.sample(all_matching_indices, min(replacement_count, len(all_matching_indices)))

    # 替换对应的行
    for index in indices_to_replace:
        predicts_list = ast.literal_eval(df.at[index, 'predicts'])
        # 将每个预测项替换为空字符串
        df.at[index, 'predicts'] = ['' for _ in predicts_list]

        # 保存到 CSV
    df.to_csv(output_file, index=True)

if __name__ == '__main__':
    # lib_name = "VulLib"
    # lib_name = "Chronos"
    lib_name = "VulLibGen"
    company_list = ["harmony"]
    extended_dir = ""
    extended_name = ""

    for company in company_list:
        thresholdList = [0.3, 0.4, 0.5, 0.6, 0.7]
        # input_file = f'./RQ3_{company}_prediction_result_final.csv'  # 修改为你的输入文件路径
        input_file = f'./{lib_name}/RQ3{extended_dir}/RQ3_{company}_prediction_result_final{extended_name}.csv'  # 修改为你的输入文件路径
        for threshold in thresholdList:
            output_file = f'./{lib_name}/RQ3{extended_dir}/{company}/threshold{threshold}_filter.csv'  # 修改为你的输出文件路径
            # output_file = f'./{company}/threshold{threshold}_filter.csv'  # 修改为你的输出文件路径
            filter_predicts(input_file, output_file, threshold)