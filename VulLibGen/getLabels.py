from VulLibGen.tf_idf import tf_idf
def getLabels(params=None):
    print(params)

    white_list = params.get('white_list')
    detect_strategy = params.get('detect_strategy')
    cve_id = params.get('cve_id')
    desc = params.get('desc')
    company = params.get('company')

    tests = [{
        "cve_id": cve_id,
        "labels": "",  # 如果有特定逻辑来决定labels的内容，请在此添加
        "desc": desc
    }]
    trains = tests
    result = ""
    if detect_strategy == 'tiny_model':
        pros_path = 'VulLibGen/white_list/label_desc.csv'
        result = tf_idf.process_data_to_json(trains,tests,pros_path,detect_strategy)
    elif detect_strategy == 'tiny_modal_white_list':
        result = tf_idf.process_data_to_json(trains,tests,"",detect_strategy)
    elif detect_strategy == 'LLM':
        pros_path = 'VulLibGen/white_list/label_desc.csv'
        result = tf_idf.process_data_to_json(trains, tests, pros_path,detect_strategy)
    print(result)
    return result




