# app.py
import urllib

import requests
from flask import Flask, jsonify, request
from flask import Flask, jsonify
# from crypt import methods

from flask import Flask
from flask import request, jsonify
from flask_cors import CORS

from flask import Flask
from flask_cors import CORS, cross_origin

app = Flask(__name__)
# r'/*' 是通配符，让本服务器所有的 URL 都允许跨域请求
CORS(app)
from llm.llm import QwenClient, DeepSeekClient, LlamaClient
from parase.c_parse import collect_dependencies
from parase.pom_parse import process_projects
from web_crawler import github
from web_crawler.avd import avd
from web_crawler.nvd import nvd
from VulLibGen.getLabels import getLabels


model_clients = {
    "qwen": QwenClient(model_name="qwen-max"),
    "deepseek": DeepSeekClient(model_name="deepseek-r1"),
    # "llama": LlamaClient(model_name="llama3.3-70b-instruct")
}

app = Flask(__name__)
CORS(app)


@app.route('/vulnerabilities/github', methods=['GET'])
def get_github_vulnerabilities():
    data = github.github()
    return jsonify(data)

@app.route('/vulnerabilities/avd', methods=['GET'])
def get_avd_vulnerabilities():
    data = avd()
    return jsonify(data)

@app.route('/vulnerabilities/nvd', methods=['GET'])
def get_nvd_vulnerabilities():
    data = nvd()
    return jsonify(data)


@app.route('/llm/query', methods=['GET'])
@cross_origin()
def get_llm_query():
    query = request.args.get("query")
    model = request.args.get("model")
    if model=='':
        model='qwen'

    if not query:
        return jsonify({"error": "Missing required parameter 'query'"}), 400
    if not model:
        return jsonify({"error": "Missing required parameter 'model'"}), 400

    try:
        client = model_clients[model]
        result = client.Think([{"role": "user", "content": query}])
        return jsonify({
            "message": "SUCCESS",
            "obj": result,
            "code":200
        })
    except Exception as e:
        return jsonify({
            "code": 400,
            "message": str(e)
        })

@app.route('/llm/repair/suggestion', methods=['POST'])  # 修正接口路径
@cross_origin()
def get_repair_suggestion():
    # 获取图片中要求的四个参数
    vulnerability_name = request.form.get("vulnerability_name")
    vulnerability_desc = request.form.get("vulnerability_desc")
    related_code = request.form.get("related_code")
    model = request.form.get("model", "qwen")  # 设置默认模型

    # 参数校验（至少需要漏洞相关信息）
    if not any([vulnerability_name, vulnerability_desc, related_code]):
        return jsonify({
            "code": 400,
            "message": "至少需要提供漏洞名称、描述或相关代码之一"
        }), 400

    # 构造完整的查询内容
    query_content = []
    if vulnerability_name:
        query_content.append(f"漏洞名称：{vulnerability_name}")
    if vulnerability_desc:
        query_content.append(f"漏洞描述：{vulnerability_desc}")
    if related_code:
        query_content.append(f"相关代码：\n{related_code}")
    query_content.append("\n根据以上信息，生成修复建议：")
    full_query = "\n\n".join(query_content)

    try:
        # 获取对应的模型客户端
        client = model_clients[model]
        # 调用模型生成建议
        result = client.Think([{"role": "user", "content": full_query}])

        # 按照接口要求构造响应格式
        return jsonify({
            "code": 200,
            "message": "success",
            "obj": {
                "fix_advise": result
            }
        })
    except KeyError:
        return jsonify({
            "code": 400,
            "message": f"不支持的模型：{model}，可用模型：{list(model_clients.keys())}"
        }), 400
    except Exception as e:
        return jsonify({
            "code": 400,
            "message": f"生成建议时出错：{str(e)}"
        }), 400


@app.route('/parse/pom_parse', methods=['GET'])
def pom_parse():
    # project_folder = request.args.get("project_folder")
    project_folder = urllib.parse.unquote(request.args.get("project_folder"))
    return process_projects(project_folder)

@app.route('/parse/c_parse',methods=['GET'])
def c_parse():
    project_folder = urllib.parse.unquote(request.args.get("project_folder"))
    return  collect_dependencies(project_folder)

@app.route('/vulnerabilities/detect', methods=['POST'])
def detect_vulnerabilities():
    # 从请求体中获取JSON数据，添加null检查
    params = request.get_json()

    if params is None:
        params = {}

    # print(params)
    data = getLabels(params=params)
    try:
        print("data=")
        print(data)
    except UnicodeEncodeError:
        print("data with unicode encoding issues")
    return jsonify(data)

@app.route('/vulnerabilities/test', methods=['POST'])
def test():
    response = requests.post(' http://10.58.0.2:5000/vulnerabilities/test')
    print(response.text)
    return response.text

if __name__ == '__main__':
    app.run(debug=True)
