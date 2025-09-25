import re
import time
import requests
from bs4 import BeautifulSoup
from web_crawler.nvd import fetch_description

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Referer": "https://github.com/advisories"
}


def _text(node, default=""):
    return node.get_text(strip=True) if node else default


def _norm_severity(s: str) -> str:
    s = (s or "").strip().title()
    if s == "Moderate": return "Medium"
    if s == "Critical": return "High"
    if s in {"High", "Medium", "Low"}: return s
    return "Low"


def parse_page(page_url):
    try:
        resp = requests.get(page_url, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        advisory_list = []
        for row in soup.select(".Box-row"):
            # 标题链接（更稳）
            title_a = row.select_one("a.Link--primary")
            if not title_a:
                continue
            summary = _text(title_a)
            href = title_a.get("href", "")
            detail_url = href if href.startswith("http") else f"https://github.com{href}"

            # ID：优先粗体，再从标题/链接里兜底找 CVE
            id_node = row.select_one(".text-bold")
            raw_id = _text(id_node)
            cve_match = CVE_RE.search(raw_id) or CVE_RE.search(summary) or CVE_RE.search(detail_url)
            vuln_id = cve_match.group(0) if cve_match else raw_id

            # 严重性与日期（都带兜底）
            severity = _norm_severity(_text(row.select_one(".Label"), "Low"))
            rt = row.select_one("relative-time")
            date = (rt.get("datetime", "")[:10]) if rt else ""

            # 创建本地描述，避免调用fetch_description导致超时
            if vuln_id and vuln_id.startswith("CVE-"):
                description = f"GitHub Security Advisory: {summary}，CVE编号：{vuln_id}，风险等级：{severity}"
            else:
                description = f"GitHub Security Advisory: {summary}，风险等级：{severity}"

            # 如果有GHSA编号，添加到描述中
            if raw_id and raw_id.startswith("GHSA-"):
                description += f"，GHSA编号：{raw_id}"

            advisory_list.append({
                "vulnerabilityName": summary,
                "cveId": vuln_id if vuln_id else None,
                "disclosureTime": date,
                "description": description,
                "riskLevel": severity,
                "referenceLink": detail_url,
                "affectsWhitelist": 0,
                "isDelete": 0,
            })

        # 分页按钮更稳的判断：有 next_page 且有 href 且未 disabled
        next_a = soup.select_one("a.next_page")
        has_next = bool(next_a and next_a.get("href") and next_a.get("aria-disabled") != "true")
        return advisory_list, has_next

    except Exception as e:
        print(f"Error processing {page_url}: {e}")
        return [], False


def github(start_page=1):
    print("Gathering security advisories from GitHub (optimized)...")
    base_url = "https://github.com/advisories?page={}&query=type%3Areviewed"
    page_num = start_page
    combined = []

    while True:
        page_url = base_url.format(page_num)
        items, has_next = parse_page(page_url)
        combined.extend(items)
        print(f"Processed page {page_num}, collected {len(items)} advisories.")

        if not has_next or page_num >= 10:
            break
        page_num += 1

    print(f"COMPLETE. Collected {len(combined)} advisories.")

    # 数据验证和清理
    try:
        from web_crawler.data_validator import validate_and_clean_vulnerability_data
        combined = validate_and_clean_vulnerability_data(combined, "github")
        print(f"Data validation complete. Final count: {len(combined)} advisories.")
    except ImportError:
        print("Data validator not available, returning raw data.")

    return combined


if __name__ == "__main__":
    import json
    start_time = time.time()
    json_data = github()  # 动态获取所有页数据
    print(f"Execution time: {time.time() - start_time:.2f} seconds")

    # 打印前三行数据
    print("Top 3 advisories:")
    print(json.dumps(json_data[:3], indent=4, ensure_ascii=False))
