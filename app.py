# app.py
from flask import Flask, jsonify

from llm.llm import QwenClient, DeepSeekClient, LlamaClient
from web_crawler import github
from web_crawler.avd import avd
from web_crawler.nvd import nvd

model_clients = {
    "qwen": QwenClient(model_name="qwen-max"),
    "deepseek": DeepSeekClient(model_name="deepseek-r1"),
    "llama": LlamaClient(model_name="llama3.3-70b-instruct")
}

app = Flask(__name__)

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

from flask import request, jsonify

@app.route('/llm/query', methods=['GET'])
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


if __name__ == '__main__':
    app.run(debug=True)
