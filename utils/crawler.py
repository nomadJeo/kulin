from turtledemo.sorting_animate import start_isort

import requests
from bs4 import BeautifulSoup

HEADERS = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# GitHub Advisory Database的URL
GITHUB_BASE_URL = "https://github.com/advisories?query=type%3Areviewed&page={}"

# 阿里云漏洞库的URL
ALIYUN_BASE_URL = "https://avd.aliyun.com?page={}"

# NVD漏洞库的URL
NVD_BASE_URL = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&startIndex={}"


def fetch_github_vulnerabilities():
    vulnerabilities = []
    page = 1

    while True:
        url = GITHUB_BASE_URL.format(page)
        print(f"Fetching page {page}: {url}")

        try:
            response = requests.get(url, headers=HEADERS)
            if response.status_code != 200:
                print(f"Failed to fetch data from page {page}: {response.status_code}")
                break  # 停止爬取

            soup = BeautifulSoup(response.text, "html.parser")
            items = soup.find_all("div", class_="Box-row")

            # 如果当前页没有数据，则认为爬取结束
            if not items:
                print("No more data available. Stopping.")
                break

            for item in items:
                try:
                    name_tag = item.find("a", class_="Link--primary")
                    if not name_tag:
                        continue

                    vulnerability_name = name_tag.text.strip()
                    reference_link = "https://github.com" + name_tag["href"]

                    severity_tag = item.find("span", class_="Label")
                    risk_level = severity_tag.text.strip() if severity_tag else "Unknown"

                    disclosure_date_tag = item.find("relative-time")
                    disclosure_date = disclosure_date_tag["datetime"] if disclosure_date_tag else "Unknown"

                    advisory_data = {
                        "vulnerability_name": vulnerability_name,
                        "disclosure_date": disclosure_date,
                        "risk_level": risk_level,
                        "reference_link": reference_link
                    }

                    vulnerabilities.append(advisory_data)
                    print(advisory_data)

                except Exception as e:
                    print(f"Error parsing item: {e}")

        except Exception as e:
            print(f"Failed to fetch data from {url}: {e}")
            break  # 遇到异常时停止

        page += 1  # 进入下一页

    return vulnerabilities


def fetch_aliyun_vulnerabilities():
    vulnerabilities = []
    page = 1

    while True:
        url = ALIYUN_BASE_URL.format(page)
        print(f"Fetching Aliyun page {page}: {url}")

        try:
            response = requests.get(url, headers=HEADERS)
            if response.status_code != 200:
                print(f"Failed to fetch data from Aliyun page {page}: {response.status_code}")
                break

            soup = BeautifulSoup(response.text, "html.parser")
            items = soup.find_all("tr")  # 处理表格行

            if not items:
                print("No more Aliyun vulnerabilities available. Stopping.")
                break

            for item in items:
                try:
                    avd_code_tag = item.find("a", href=True)
                    if avd_code_tag:
                        avd_code = avd_code_tag.text.strip()
                        vulnerability_link = "https://avd.aliyun.com"+avd_code_tag["href"]  # 从<a>标签中直接获取链接

                        detail_response = requests.get(vulnerability_link, headers=HEADERS)
                        if detail_response.status_code != 200:
                            print(f"Failed to fetch detail page")
                            continue

                        detail_soup = BeautifulSoup(detail_response.text, "html.parser")
                        # 获取漏洞名称
                        print(detail_soup.prettify())
                        vuln_name_tag = detail_soup.find("span", class_="header__title_text")
                        vulnerability_name = vuln_name_tag.text.strip() if vuln_name_tag else "Unknown"

                        # 获取风险等级
                        risk_level_tag = detail_soup.find("span", class_="badge btn-warning")
                        risk_level = risk_level_tag.text.strip() if risk_level_tag else "Unknown"

                        # 获取披露时间
                        date_tag = detail_soup.find("div", class_="metric-value")
                        disclosure_date = date_tag.text.strip() if date_tag else "Unknown"


                        advisory_data = {
                            "vulnerability_name": vulnerability_name,
                            "disclosure_date": disclosure_date,
                            "risk_level": risk_level,
                            "reference_link": vulnerability_link
                        }

                        vulnerabilities.append(advisory_data)

                except Exception as e:
                    print(f"Error parsing Aliyun item: {e}")

        except Exception as e:
            print(f"Failed to fetch data from Aliyun: {e}")
            break

        page += 1

    return vulnerabilities


def fetch_nvd_vulnerabilities():
    vulnerabilities = []
    startIndex = 0

    while True:
        url = NVD_BASE_URL.format(startIndex)

        try:
            response = requests.get(url, headers=HEADERS)
            if response.status_code != 200:
                print(f"Failed to fetch data from startIndex {startIndex}: {response.status_code}")
                break

            soup = BeautifulSoup(response.text, "html.parser")
            for row in soup.find_all("tr", {"data-testid": lambda x: x and x.startswith("vuln-row-")}):
                try:

                    desc_tag = row.find("p", {"data-testid": lambda x: x and x.startswith("vuln-summary-")})
                    vulnerability_name = desc_tag.text.strip() if desc_tag else "No description available"

                    # 获取漏洞名称及链接
                    cve_tag = row.find("a", {"data-testid": lambda x: x and x.startswith("vuln-detail-link-")})
                    reference_link = "https://nvd.nist.gov" + cve_tag["href"]

                    # 获取披露日期
                    date_tag = row.find("span", {"data-testid": lambda x: x and x.startswith("vuln-published-on-")})
                    disclosure_date = date_tag.text.strip() if date_tag else "Unknown"

                    # 获取风险等级（可选，具体请确认 HTML 结构是否包含）
                    risk_tag = row.find("td", {"nowrap": "nowrap"})
                    risk_level = risk_tag.text.strip() if risk_tag else "Unknown"

                    vulnerabilities.append({
                        "vulnerability_name": vulnerability_name,
                        "disclosure_date": disclosure_date,
                        "risk_level": risk_level,
                        "reference_link": reference_link
                    })

                except Exception as e:
                    print(f"Error parsing vulnerability row: {e}")
            startIndex += 20

        except Exception as e:
            print(f"Failed to fetch data from NIST: {e}")
            break


    return vulnerabilities

def fetch_vulnerabilities():
    #github_vulnerabilities = fetch_github_vulnerabilities()
    aliyun_vulnerabilities = fetch_aliyun_vulnerabilities()
    #nvd_vulnerabilities = fetch_nvd_vulnerabilities()


    #all_vulnerabilities = nvd_vulnerabilities
    #return all_vulnerabilities


if __name__ == "__main__":
    all_vulnerabilities = fetch_vulnerabilities()
    print(f"Total vulnerabilities fetched: {len(all_vulnerabilities)}")
    for vuln in all_vulnerabilities:
        print(vuln)
