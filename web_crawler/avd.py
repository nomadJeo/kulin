import re

import requests
from bs4 import BeautifulSoup
from distributed.utils_test import security

HEADERS = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# 阿里云漏洞库的URL
ALIYUN_BASE_URL = "https://avd.aliyun.com?page={}"

def avd():
    page = 1

    while True:
        if page > 1:
            break
        url = ALIYUN_BASE_URL.format(page)
        print(f"Fetching Aliyun page {page}: {url}")
        data = []

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
                        vul_name = item.contents[3].text.strip()
                        vul_date = item.contents[7].text.strip()
                        riskLevel = re.sub(r'\s+', ' ', item.contents[9].text).replace("\n", " ").strip()
                        URL = "https://avd.aliyun.com"+avd_code_tag["href"]  # 从<a>标签中直接获取链接
                        data.append({
                            "vulnerabilityName": f"{avd_code}: {vul_name}",
                            "disclosureTime": vul_date,
                            "riskLevel": riskLevel,
                            "referenceLink": URL,
                            "affectsWhitelist": 0,
                            "isDelete": 0
                        })

                except Exception as e:
                    print(f"Error parsing Aliyun item: {e}")

        except Exception as e:
            print(f"Failed to fetch data from Aliyun: {e}")
            break

        page +=1


    return data


if __name__ == "__main__":
    data = avd()
    print(data)