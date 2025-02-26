import pandas as pd
import json
import sys


def csv_to_json(csv_file_path, json_file_path):
    # 尝试读取 CSV 文件，指定第一列作为索引，并处理可能存在的格式问题
    try:
        df = pd.read_csv(csv_file_path, encoding='utf-8', on_bad_lines='skip', quotechar='"', escapechar='\\',
                         index_col=0)
    except Exception as e:
        print(f"Error reading CSV file: {e}", file=sys.stderr)
        return

    # 替换 NaN 值为空字符串
    df.fillna('', inplace=True)

    # 将整个 DataFrame 转换为字典列表
    data = df.reset_index(drop=True).to_dict(orient='records')  # 使用 reset_index(drop=True) 删除索引

    # 写入 JSON 文件，确保使用 utf-8 编码并处理非 ASCII 字符
    try:
        with open(json_file_path, 'w', encoding='utf-8') as json_file:
            json.dump(data, json_file, ensure_ascii=False, indent=4)
        print(f"Conversion completed. JSON file saved to {json_file_path}")
    except Exception as e:
        print(f"An error occurred while writing the JSON file: {e}", file=sys.stderr)


if __name__ == '__main__':
    # 指定输入和输出文件路径
    input_csv = '/Users/mac/Desktop/kulin/VulLibGen/white_list/label_desc.csv'
    output_json = '/Users/mac/Desktop/kulin/VulLibGen/white_list/label_desc.json'

    # 执行转换
    csv_to_json(input_csv, output_json)