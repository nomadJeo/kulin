
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
def fetch_nvd_vulnerabilities_api() -> List[Dict]:
    """
    使用NVD官方API获取漏洞数据，替代网页爬虫方式
    """
    print("使用NVD官方API获取数据...")

    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    }

    params = {
        "resultsPerPage": 20,  # 每页20条
        "startIndex": 0
    }

    results: List[Dict] = []

    try:
        # 获取3页数据，共60条
        for page in range(3):
            params["startIndex"] = page * 20

            response = requests.get(api_url, headers=headers, params=params, timeout=30)
            if response.status_code != 200:
                print(f"API请求失败: {response.status_code}")
                break

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            print(f"API第{page+1}页获取到 {len(vulnerabilities)} 条数据")

            for vuln_data in vulnerabilities:
                try:
                    cve = vuln_data.get("cve", {})
                    cve_id = cve.get("id", "Unknown")

                    # 获取英文描述
                    descriptions = cve.get("descriptions", [])
                    description = "No description available"
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "No description available")
                            break

                    # 获取发布日期
                    published = cve.get("published", "")
                    disclosure_date = published[:10] if published else "Unknown"

                    # 获取CVSS评分和风险等级
                    risk_level = "Medium"  # 默认
                    base_score = None
                    metrics = cve.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV3", [])
                    if cvss_v3:
                        base_score = cvss_v3[0].get("cvssData", {}).get("baseScore", 0)
                        if base_score >= 7.0:
                            risk_level = "High"
                        elif base_score >= 4.0:
                            risk_level = "Medium"
                        else:
                            risk_level = "Low"

                    # 从描述中提取有意义的漏洞名称，而不是只用CVE编号
                    vulnerability_name = cve_id  # 默认使用CVE编号
                    if description and len(description) > 20:
                        # 尝试从描述中提取前50个字符作为更有意义的名称
                        desc_words = description.split()
                        if len(desc_words) >= 3:
                            # 取前几个关键词组成漏洞名称
                            vulnerability_name = " ".join(desc_words[:8])
                            if len(vulnerability_name) > 80:
                                vulnerability_name = vulnerability_name[:77] + "..."

                    results.append({
                        "vulnerabilityName": vulnerability_name,
                        "cveId": cve_id,
                        "description": description,
                        "disclosureTime": disclosure_date,
                        "riskLevel": risk_level,
                        "referenceLink": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "affectsWhitelist": 0,
                        "isDelete": 0,
                    })

                except Exception as e:
                    print(f"解析漏洞数据出错: {e}")

            if len(vulnerabilities) < 20:  # 如果返回数据少于20条，说明没有更多数据
                break

    except Exception as e:
        print(f"NVD API请求异常: {e}")
        # 如果API失败，返回一些fallback数据
        results = [
            {
                "vulnerabilityName": "NVD API服务暂时不可用",
                "cveId": "CVE-FALLBACK-001",
                "description": "NVD API暂时不可用，这是示例漏洞数据",
                "disclosureTime": "2024-01-01",
                "riskLevel": "Medium",
                "referenceLink": "https://nvd.nist.gov",
                "affectsWhitelist": 0,
                "isDelete": 0,
            }
        ]

    # 数据验证和清理
    try:
        from web_crawler.data_validator import validate_and_clean_vulnerability_data
        results = validate_and_clean_vulnerability_data(results, "nvd")
        print(f"Data validation complete. Final count: {len(results)} advisories.")
    except ImportError:
        print("Data validator not available, returning raw data.")

    return results


def fetch_description(cve_id: str) -> str:
    """
    与原功能一致：在 NVD 查询页上抓取第一条摘要描述。
    """
    if not cve_id:
        return "Not cve id,No description available"

    with requests.Session() as session:
        url = NVD_QUERY_URL.format(cve_id)
        soup = _get_soup(session, url)
        if not soup:
            return "Not soup,No description available"

        desc_tag = _find_first_by_testid_prefix(soup, _SUMMARY_PREFIX)
        return desc_tag.get_text(strip=True) if desc_tag else "Not desc_tag,No description available"


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
    return fetch_nvd_vulnerabilities_api()


if __name__ == "__main__":
    import json

    # 获取漏洞数据
    data = nvd()
    print(f"成功获取 {len(data)} 条NVD漏洞数据")

    # 打印前三条数据
    if data:
        print("\nNVD前3条漏洞数据:")
        print(json.dumps(data[:3], indent=4, ensure_ascii=False))
    else:
        print("未获取到任何漏洞数据")
