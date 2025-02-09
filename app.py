# app.py
from flask import Flask, jsonify
from web_crawler import github
from web_crawler.avd import avd
from web_crawler.nvd import nvd

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


if __name__ == '__main__':
    app.run(debug=True)
