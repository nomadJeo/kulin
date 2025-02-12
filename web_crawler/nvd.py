import requests
from bs4 import BeautifulSoup

HEADERS = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# NVD漏洞库的URL
NVD_BASE_URL = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&startIndex={}"

def fetch_nvd_vulnerabilities():
    vulnerabilities = []
    startIndex = 0

    while True:
        url = NVD_BASE_URL.format(startIndex)
        if startIndex > 2000:
            break

        try:
            response = requests.get(url, headers=HEADERS)
            if response.status_code != 200:
                print(f"Failed to fetch data from startIndex {startIndex}: {response.status_code}")
                break

            print(f"Success to fetch data from startIndex {startIndex}")
            soup = BeautifulSoup(response.text, "html.parser")
            for row in soup.find_all("tr", {"data-testid": lambda x: x and x.startswith("vuln-row-")}):
                try:

                    desc_tag = row.find("p", {"data-testid": lambda x: x and x.startswith("vuln-summary-")})
                    vulnerability_name = desc_tag.text.strip() if desc_tag else "No description available"

                    # 获取漏洞名称及链接
                    cve_tag = row.find("a", {"data-testid": lambda x: x and x.startswith("vuln-detail-link-")})
                    vulnerability_id = cve_tag.text.strip() if cve_tag else "Unknown"
                    reference_link = "https://nvd.nist.gov" + cve_tag["href"]

                    # 获取披露日期
                    date_tag = row.find("span", {"data-testid": lambda x: x and x.startswith("vuln-published-on-")})
                    disclosure_date = convert_date(date_tag.text.strip() if date_tag else "Unknown")

                    # 获取风险等级（可选，具体请确认 HTML 结构是否包含）
                    risk_tag = row.find("td", {"nowrap": "nowrap"})
                    risk_level = risk_tag.text.strip() if risk_tag else "Unknown"

                    vulnerabilities.append({
                        "vulnerabilityName": vulnerability_id,
                        "disclosureTime": disclosure_date,
                        "riskLevel": risk_level,
                        "referenceLink": reference_link,
                        "affectsWhitelist": 0,
                        "isDelete": 0
                    })

                except Exception as e:
                    print(f"Error parsing vulnerability row: {e}")
            startIndex += 20

        except Exception as e:
            print(f"Failed to fetch data from NIST: {e}")
            break


    return vulnerabilities

def fetch_description(cve_id):
    base_url = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={}&search_type=all&isCpeNameSearch=false"
    url = base_url.format(cve_id)
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        return "No description available"

    soup = BeautifulSoup(response.text, "html.parser")
    desc_tag = soup.find("p", {"data-testid": lambda x: x and x.startswith("vuln-summary-")})
    return desc_tag.text.strip() if desc_tag else "No description available"

from datetime import datetime


def convert_date(date_str):
    # 解析带有时区的日期字符串
    date_obj = datetime.strptime(date_str, "%B %d, %Y; %I:%M:%S %p %z")

    # 将 datetime 对象转换为新的字符串格式
    return date_obj.strftime("%Y-%m-%d")

def nvd():
    print("Gathering security advisories from NVD...")
    return fetch_nvd_vulnerabilities()

if __name__ == "__main__":
    nvd()
