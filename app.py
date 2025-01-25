# app.py
from flask import Flask, jsonify
from utils.crawler import fetch_github_vulnerabilities

app = Flask(__name__)

@app.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    vulnerabilities = fetch_github_vulnerabilities()
    return jsonify(vulnerabilities)

if __name__ == '__main__':
    app.run(debug=True)
