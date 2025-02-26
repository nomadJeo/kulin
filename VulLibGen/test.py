from tf_idf.tf_idf import process_data_to_json
# 调用示例
if __name__ == '__main__':
    params = {
        'cve_id': 'CVE-2023-1234',
        'desc': 'This is a sample description.'
    }

    trains = [{
        "cve_id": params.get('cve_id'),
        "labels": [],  # 根据实际情况填充
        "desc": params.get('desc')
    }]

    tests = trains.copy()  # 或者根据实际情况定义tests

    pros_path = '../VulLibGen/white_list/label_desc.csv'
    print(1)
    result_json = process_data_to_json(trains, tests, pros_path)
    print(result_json)  # 输出将是JSON格式的new_test

