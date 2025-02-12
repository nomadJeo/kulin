from pydoc import pager

import requests
from bs4 import BeautifulSoup
import time

from web_crawler.nvd import fetch_description

# 禁用安全请求警告（仅用于示例）
requests.packages.urllib3.disable_warnings()

def parse_page(page_url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    try:
        response = requests.get(page_url, headers=headers, timeout=15, verify=False)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        advisory_list = []
        for row in soup.select('.Box-row'):
            vuln_id = row.select_one('.text-bold').get_text(strip=True)
            if vuln_id.startswith("GHSA"):
                continue
            summary = row.select_one('.Link--primary').get_text(strip=True)
            description = fetch_description(vuln_id)
            if description=="No description available":
                continue
            severity = row.select_one('.Label').get_text(strip=True)
            date = row.select_one('relative-time')['datetime'].split('T')[0]
            url = row.select_one('a')['href']

            advisory_list.append({
                "vulnerabilityName": summary,
                "cveId": vuln_id,
                "disclosureTime": date,
                "description": description,
                "riskLevel": severity,
                "referenceLink": 'https://github.com'+url,
                "affectsWhitelist":0,
                "isDelete":0
            })

        next_page = soup.select_one('a.next_page')
        has_next = bool(next_page)

        return advisory_list, has_next
    except Exception as e:
        print(f"Error processing {page_url}: {str(e)}")
        return [], False


def github(start_page=1):
    print("Gathering security advisories from GitHub (optimized)...")

    base_url = "https://github.com/advisories?page={}&query=type%3Areviewed"
    page_num = start_page
    combined = []

    while True:
        page_url = base_url.format(page_num)
        advisory_list, has_next = parse_page(page_url)
        combined.extend(advisory_list)

        print(f"Processed page {page_num}, collected {len(advisory_list)} advisories.")

        if not has_next:
            break

        if page_num >= 10:
            break

        page_num += 1

    print(f"COMPLETE. Collected {len(combined)} advisories.")
    return combined



if __name__ == "__main__":
    start_time = time.time()
    json_data = github()  # 动态获取所有页数据
    print(f"Execution time: {time.time() - start_time:.2f} seconds")
    print(json_data)
