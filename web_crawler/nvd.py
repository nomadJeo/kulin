# import requests
# from bs4 import BeautifulSoup
#
# HEADERS = {
#       "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
# }
#
# # NVD漏洞库的URL
# NVD_BASE_URL = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&startIndex={}"
#
# def fetch_nvd_vulnerabilities():
#     vulnerabilities = []
#     startIndex = 0
#
#     while True:
#         url = NVD_BASE_URL.format(startIndex)
#         if startIndex > 2000:
#             break
#
#         try:
#             response = requests.get(url, headers=HEADERS)
#             if response.status_code != 200:
#                 print(f"Failed to fetch data from startIndex {startIndex}: {response.status_code}")
#                 break
#
#             print(f"Success to fetch data from startIndex {startIndex}")
#             soup = BeautifulSoup(response.text, "html.parser")
#             for row in soup.find_all("tr", {"data-testid": lambda x: x and x.startswith("vuln-row-")}):
#                 try:
#
#                     desc_tag = row.find("p", {"data-testid": lambda x: x and x.startswith("vuln-summary-")})
#                     description = desc_tag.text.strip() if desc_tag else "No description available"
#
#                     # 获取漏洞名称及链接
#                     cve_tag = row.find("a", {"data-testid": lambda x: x and x.startswith("vuln-detail-link-")})
#                     vulnerability_id = cve_tag.text.strip() if cve_tag else "Unknown"
#                     reference_link = "https://nvd.nist.gov" + cve_tag["href"]
#
#                     # 获取披露日期
#                     date_tag = row.find("span", {"data-testid": lambda x: x and x.startswith("vuln-published-on-")})
#                     disclosure_date = convert_date(date_tag.text.strip() if date_tag else "Unknown")
#
#                     # 获取风险等级（可选，具体请确认 HTML 结构是否包含）
#                     risk_tag = row.find("td", {"nowrap": "nowrap"})
#                     risk_level = 'Medium'
#                     risk = risk_tag.text.strip() if risk_tag else "Unknown"
#                     if risk.__contains__('HIGH'):
#                         risk_level = 'High'
#                     if risk.__contains__('LOW'):
#                         risk_level = 'Low'
#                     if risk.__contains__('MEDIUM'):
#                         risk_level = 'Medium'
#
#                     vulnerabilities.append({
#                         "vulnerabilityName": vulnerability_id,
#                         "cveId":vulnerability_id,
#                         "description": description,
#                         "disclosureTime": disclosure_date,
#                         "riskLevel": risk_level,
#                         "referenceLink": reference_link,
#                         "affectsWhitelist": 0,
#                         "isDelete": 0
#                     })
#
#                 except Exception as e:
#                     print(f"Error parsing vulnerability row: {e}")
#             startIndex += 20
#
#         except Exception as e:
#             print(f"Failed to fetch data from NIST: {e}")
#             break
#
#
#     return vulnerabilities
#
# def fetch_description(cve_id):
#     base_url = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={}&search_type=all&isCpeNameSearch=false"
#     url = base_url.format(cve_id)
#     response = requests.get(url, headers=HEADERS)
#     if response.status_code != 200:
#         return "No description available"
#
#     soup = BeautifulSoup(response.text, "html.parser")
#     desc_tag = soup.find("p", {"data-testid": lambda x: x and x.startswith("vuln-summary-")})
#     return desc_tag.text.strip() if desc_tag else "No description available"
#
# from datetime import datetime
#
#
# def convert_date(date_str):
#     # 解析带有时区的日期字符串
#     date_obj = datetime.strptime(date_str, "%B %d, %Y; %I:%M:%S %p %z")
#
#     # 将 datetime 对象转换为新的字符串格式
#     return date_obj.strftime("%Y-%m-%d")
#
# def fetch_riskLevel(cve_id):
#     base_url = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={}&search_type=all&isCpeNameSearch=false"
#     url = base_url.format(cve_id)
#     response = requests.get(url, headers=HEADERS)
#     if response.status_code != 200:
#         return "No description available"
#
#     soup = BeautifulSoup(response.text, "html.parser")
#     risk_tag = soup.find("td", {"nowrap": "nowrap"})
#     risk_level = 'Medium'
#     risk = risk_tag.text.strip() if risk_tag else "Unknown"
#     if risk.__contains__('HIGH'):
#         risk_level = 'High'
#     if risk.__contains__('LOW'):
#         risk_level = 'Low'
#     if risk.__contains__('MEDIUM'):
#         risk_level = 'Medium'
#     return risk_level
#
# def nvd():
#     print("Gathering security advisories from NVD...")
#     return fetch_nvd_vulnerabilities()
#
# if __name__ == "__main__":
#     fetch_riskLevel("CVE-2024-13345")
import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# --------------------------
# 常量 & 复用会话
# --------------------------
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/91.0.4472.124 Safari/537.36"
}

# NVD 漏洞库列表页（20 条/页）
NVD_BASE_URL = ("https://nvd.nist.gov/vuln/search/results"
                "?form_type=Basic&results_type=overview&search_type=all"
                "&isCpeNameSearch=false&startIndex={}")

# NVD 搜索页（按 CVE 查询）
NVD_QUERY_URL = ("https://nvd.nist.gov/vuln/search/results"
                 "?form_type=Basic&results_type=overview&query={}"
                 "&search_type=all&isCpeNameSearch=false")

_ROW_PREFIX = "vuln-row-"
_SUMMARY_PREFIX = "vuln-summary-"
_DETAIL_LINK_PREFIX = "vuln-detail-link-"
_PUBLISHED_PREFIX = "vuln-published-on-"

# --------------------------
# 工具函数
# --------------------------
def _get_soup(session: requests.Session, url: str) -> Optional[BeautifulSoup]:
    """请求页面并返回 BeautifulSoup；失败返回 None。"""
    try:
        resp = session.get(url, headers=HEADERS, timeout=15)
        if resp.status_code != 200:
            print(f"HTTP {resp.status_code} for {url}")
            return None
        # 这里用内置解析器以避免额外依赖；若已安装 lxml，可改为 'lxml'
        return BeautifulSoup(resp.text, "html.parser")
    except Exception as e:
        print(f"Request error for {url}: {e}")
        return None


def _parse_date(date_str: str) -> str:
    """
    将 NVD 页面上的时间字符串转为 YYYY-MM-DD。
    原实现要求格式：%B %d, %Y; %I:%M:%S %p %z
    这里做多格式容错，功能保持为“输出 YYYY-MM-DD”。
    """
    if not date_str:
        return "Unknown"
    patterns = [
        "%B %d, %Y; %I:%M:%S %p %z",  # e.g. April 03, 2024; 10:22:33 AM +00:00
        "%B %d, %Y %I:%M:%S %p %z",   # 少分号的兜底
        "%B %d, %Y",                  # 只有日期
    ]
    for fmt in patterns:
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.strftime("%Y-%m-%d")
        except Exception:
            continue
    # 全部失败则保持兼容：返回 "Unknown"
    return "Unknown"


def _parse_risk_level(cell_text: str) -> str:
    """
    按原逻辑：默认 Medium；包含 HIGH→High，LOW→Low，MEDIUM→Medium。
    这里大小写无关且更直观。
    """
    s = (cell_text or "").upper()
    if "HIGH" in s:
        return "High"
    if "LOW" in s:
        return "Low"
    # MEDIUM 或其他 → Medium（与原功能一致）
    return "Medium"


def _select_first(soup: BeautifulSoup, selector: str):
    node = soup.select_one(selector)
    return node


def _find_first_by_testid_prefix(tag: BeautifulSoup, prefix: str):
    """
    兼容 data-testid 以某前缀开头的节点查找（等价于原 lambda startswith）。
    """
    return tag.find(attrs={"data-testid": re.compile(rf"^{re.escape(prefix)}")})


def _find_all_rows_by_prefix(soup: BeautifulSoup, prefix: str):
    return soup.find_all("tr", attrs={"data-testid": re.compile(rf"^{re.escape(prefix)}")})


# --------------------------
# 对外：与原接口等价的函数
# --------------------------
def fetch_nvd_vulnerabilities() -> List[Dict]:
    """
    功能不变：
    - 从 NVD 列表页按 20 条分页抓取（startIndex 每次 +20）
    - 超过 2000 时停止
    - 字段保持：vulnerabilityName/cveId/description/disclosureTime/riskLevel/referenceLink/affectsWhitelist/isDelete
    """
    results: List[Dict] = []
    start_index = 0

    with requests.Session() as session:
        while True:
            if start_index > 2000:  # 与原逻辑一致
                break

            url = NVD_BASE_URL.format(start_index)
            soup = _get_soup(session, url)
            if not soup:
                break

            print(f"Success to fetch data from startIndex {start_index}")

            rows = _find_all_rows_by_prefix(soup, _ROW_PREFIX)
            for row in rows:
                try:
                    # 描述
                    desc_tag = _find_first_by_testid_prefix(row, _SUMMARY_PREFIX)
                    description = desc_tag.get_text(strip=True) if desc_tag else "No description available"

                    # 漏洞名称/链接（CVE）
                    cve_tag = _find_first_by_testid_prefix(row, _DETAIL_LINK_PREFIX)
                    if not cve_tag:
                        vulnerability_id = "Unknown"
                        reference_link = ""
                    else:
                        vulnerability_id = cve_tag.get_text(strip=True) or "Unknown"
                        href = cve_tag.get("href", "")
                        reference_link = f"https://nvd.nist.gov{href}" if href else ""

                    # 披露日期
                    date_tag = _find_first_by_testid_prefix(row, _PUBLISHED_PREFIX)
                    disclosure_date_raw = date_tag.get_text(strip=True) if date_tag else "Unknown"
                    disclosure_date = _parse_date(disclosure_date_raw)

                    # 风险等级（沿用原查找思路：行里找 nowrap=nowrap 的单元格文本）
                    risk_cell = row.find("td", attrs={"nowrap": "nowrap"})
                    risk_level = _parse_risk_level(risk_cell.get_text(strip=True) if risk_cell else "")

                    results.append({
                        "vulnerabilityName": vulnerability_id,
                        "cveId": vulnerability_id,
                        "description": description,
                        "disclosureTime": disclosure_date,
                        "riskLevel": risk_level,
                        "referenceLink": reference_link,
                        "affectsWhitelist": 0,
                        "isDelete": 0
                    })
                except Exception as e:
                    print(f"Error parsing vulnerability row: {e}")

            start_index += 20

    return results


def fetch_description(cve_id: str) -> str:
    """
    与原功能一致：在 NVD 查询页上抓取第一条摘要描述。
    """
    if not cve_id:
        return "No description available"

    with requests.Session() as session:
        url = NVD_QUERY_URL.format(cve_id)
        soup = _get_soup(session, url)
        if not soup:
            return "No description available"

        desc_tag = _find_first_by_testid_prefix(soup, _SUMMARY_PREFIX)
        return desc_tag.get_text(strip=True) if desc_tag else "No description available"


def convert_date(date_str: str) -> str:
    """
    保持原函数名与用途不变：输入页面原始日期字符串 → 返回 YYYY-MM-DD。
    内部调用更健壮的 _parse_date。
    """
    return _parse_date(date_str)


def fetch_riskLevel(cve_id: str) -> str:
    """
    与原功能一致：到查询页抓一条记录，按单元格文本解析风险等级。
    """
    if not cve_id:
        return "No description available"

    with requests.Session() as session:
        url = NVD_QUERY_URL.format(cve_id)
        soup = _get_soup(session, url)
        if not soup:
            return "No description available"

        risk_cell = soup.find("td", attrs={"nowrap": "nowrap"})
        return _parse_risk_level(risk_cell.get_text(strip=True) if risk_cell else "")


def nvd() -> List[Dict]:
    print("Gathering security advisories from NVD...")
    return fetch_nvd_vulnerabilities()


if __name__ == "__main__":
    # 小自测：不改变对外行为
    print(fetch_riskLevel("CVE-2024-13345"))
    # 打印部分漏洞报告
    print()
