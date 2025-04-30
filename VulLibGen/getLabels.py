from VulLibGen.tf_idf import tf_idf
import requests
# from VulLibGen.tf_idf.threshold_cal import process_librariesf
from VulLibGen.vuldet_utils.datasetConstructor import format, convert_to_compact_format
import json
import csv
import tempfile
def getLabels(params=None):
    print(params)

    language = params.get('language')
    white_list = params.get('white_list')
    detect_strategy = params.get('detect_strategy')
    cve_id = params.get('cve_id')
    desc = params.get('desc')
    company = params.get('company')
    similarityThreshold = params.get('similarityThreshold')

    tests = [{
        "cve_id": cve_id,
        "labels": "",  # 如果有特定逻辑来决定labels的内容，请在此添加
        "desc": desc
    }]
    trains = tests
    result = ""
    if detect_strategy == 'TinyModel' or detect_strategy == 'TinyModel-lev' or detect_strategy == 'TinyModel-cos' or detect_strategy == 'TinyModel-lcs':
        if language == 'java':
            pros_path = 'VulLibGen/white_list/label_desc.csv'
            packages_file_path = 'VulLibGen/white_list/label_desc.json'
        elif language == 'c':
            pros_path = 'VulLibGen/white_list/label_desc_c.csv'
            packages_file_path = 'VulLibGen/white_list/label_desc_c.json'
        result = tf_idf.tiny_model_process_data_to_json(trains,tests,pros_path,detect_strategy,language,similarityThreshold)

        # 创建临时JSON文件
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as json_temp_file:
            json.dump(white_list, json_temp_file, ensure_ascii=False, indent=4)
            json_temp_file_path = json_temp_file.name
            print(f"JSON临时文件已创建: {json_temp_file_path}")

        if detect_strategy == 'TinyModel-lev':
            result = process_libraries(similarityThreshold,"lev",result,json_temp_file_path)
        if detect_strategy == 'TinyModel-cos':
            result = process_libraries(similarityThreshold,"cos",result,json_temp_file_path)
        if detect_strategy == 'TinyModel-lcs':
            result = process_libraries(similarityThreshold,"lcs",result,json_temp_file_path)


    elif detect_strategy == 'LLM' or detect_strategy == 'LLM-lev' or detect_strategy == 'LLM-cos' or detect_strategy == 'LLM-lcs':
        if language == 'java':
            pros_path = 'VulLibGen/white_list/label_desc.csv'
            packages_file_path = pros_json_path = 'VulLibGen/white_list/label_desc.json'
        elif language == 'c':
            pros_path = 'VulLibGen/white_list/label_desc_c.csv'
            packages_file_path = pros_json_path = 'VulLibGen/white_list/label_desc_c.json'
        result = tf_idf.llm_process_data_to_json(trains, tests, pros_path,pros_json_path,detect_strategy,language,similarityThreshold)

        # 创建临时JSON文件
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as json_temp_file:
            json.dump(white_list, json_temp_file, ensure_ascii=False, indent=4)
            json_temp_file_path = json_temp_file.name
            print(f"JSON临时文件已创建: {json_temp_file_path}")
        with open(json_temp_file_path, 'r', encoding='utf-8') as f:
            print(f"Temp file content before processing: {f.read()}")


        if detect_strategy == 'LLM-lev':
            result = process_libraries(similarityThreshold,"lev",result,json_temp_file_path)
        if detect_strategy == 'LLM-cos':
            result = process_libraries(similarityThreshold,"cos",result,json_temp_file_path)
        if detect_strategy == 'LLM-lcs':
            result = process_libraries(similarityThreshold,"lcs",result,json_temp_file_path)

    elif detect_strategy == 'TinyModel-whiteList' or detect_strategy == 'LLM-whiteList':
        # 创建临时JSON文件
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as json_temp_file:
            json.dump(white_list, json_temp_file, ensure_ascii=False, indent=4)
            json_temp_file_path = json_temp_file.name
            print(f"JSON临时文件已创建: {json_temp_file_path}")

        # 创建临时CSV文件
        with tempfile.NamedTemporaryFile(mode='w+', newline='', delete=False, suffix='.csv') as csv_temp_file:
            # 解析white_list字符串为Python对象
            white_list_parsed = json.loads(white_list)

            # 创建临时CSV文件
            with tempfile.NamedTemporaryFile(mode='w+', newline='', delete=False, suffix='.csv') as csv_temp_file:
                fieldnames = ['id', 'name', 'summary']
                writer = csv.DictWriter(csv_temp_file, fieldnames=fieldnames)
                writer.writeheader()
                for idx, item in enumerate(white_list_parsed):
                    writer.writerow({'id': idx, 'name': item['name'],
                                     'summary': item['desc']})  # 注意这里将'desc'改为'summary'以匹配fieldnames
                csv_temp_file_path = csv_temp_file.name
                print(f"CSV临时文件已创建: {csv_temp_file_path}")
        if detect_strategy == 'TinyModel-whiteList':
            result = tf_idf.tiny_model_process_data_to_json(trains, tests, csv_temp_file_path, detect_strategy,language.similarityThreshold)
        if detect_strategy == 'LLM-whiteList':
            result = tf_idf.llm_process_data_to_json(trains, tests, csv_temp_file_path, json_temp_file_path, detect_strategy,language,similarityThreshold)

    elif detect_strategy == 'VulDet':
        result = format(cve_id)
        print("VulDet Input: ")
        print(result)

        # POST 请求, 要求 url 为 VulDet 大模型的访问接口
        response = requests.post(
            url="http://127.0.0.1:6006/generate",
            headers={"Content-Type": "application/json"},
            data=json.dumps(result)
        )

        # 处理响应结果
        if response.status_code == 200:
            print("VulDet Output: ")
            # 格式为 [ [package_manager, package_name, affected_version], ... ]
            result = response.json()["output"]
        else:
            print(f"请求失败，状态码：{response.status_code}")
            print(response.text)


    print(result)
    return result




