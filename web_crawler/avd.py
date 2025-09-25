import re
import requests
from bs4 import BeautifulSoup
from web_crawler.nvd import fetch_description, fetch_riskLevel
import json

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}
ALIYUN_BASE_URL = "https://avd.aliyun.com?page={}"

def avd():
    print("Gathering security advisories from Aliyun AVD...")
    page = 1
    data = []   # ← 汇总

    while True:
        if page > 1:
            break  # 先只抓第 1 页，确认结构
        url = ALIYUN_BASE_URL.format(page)
        print(f"Fetching Aliyun page {page}: {url}")

        try:
            resp = requests.get(url, headers=HEADERS, timeout=15)
            print("status:", resp.status_code, "len:", len(resp.text))
            if resp.status_code != 200:
                print("Bad status, stop.")
                break

            # 保存 HTML 方便你本地打开看结构/是否是风控页
            open(f"avd_p{page}.html", "w", encoding="utf-8").write(resp.text)

            soup = BeautifulSoup(resp.text, "lxml")  # lxml 解析更稳

            rows = soup.select("table tbody tr")
            if not rows:
                print("No rows found. Page might be JS-rendered or anti-scraped.")
                break

            for row in rows:
                try:
                    tds = row.find_all("td")
                    if len(tds) < 4:
                        continue
                    # 获取AVD链接和编号
                    link = tds[0].find("a", href=True)
                    if not link:
                        continue

                    avd_id = link.get_text(strip=True)
                    URL = "https://avd.aliyun.com" + link["href"]

                    # 漏洞名称
                    vul_name = tds[1].get_text(strip=True)

                    # 漏洞类型（第3列）
                    vul_type_element = tds[2].find("button")
                    vul_type = vul_type_element.get_text(strip=True) if vul_type_element else "未定义"

                    # 披露时间（第4列）
                    vul_date = tds[3].get_text(strip=True)

                    # 从漏洞名称中提取 CVE
                    cve_match = re.search(r"CVE-\d{4}-\d+", vul_name)
                    cve_id = cve_match.group(0) if cve_match else None

                    # 创建本地描述，避免调用fetch_description导致超时
                    if cve_id:
                        description = f"阿里云漏洞库收录的{vul_type}类型漏洞，CVE编号：{cve_id}，漏洞名称：{vul_name}"
                    else:
                        description = f"阿里云漏洞库收录的{vul_type}类型漏洞，漏洞名称：{vul_name}"

                    # 根据漏洞类型设置风险等级
                    risk_level = "Medium"  # 默认中等
                    if any(keyword in vul_name.lower() for keyword in ["远程代码执行", "代码执行", "命令执行", "提权"]):
                        risk_level = "High"
                    elif any(keyword in vul_name.lower() for keyword in ["信息泄漏", "信息披露", "拒绝服务"]):
                        risk_level = "Low"
                    # 为null的cveId生成默认值，避免数据库插入失败
                    if not cve_id:
                        # 使用AVD ID作为fallback cveId
                        cve_id = avd_id if avd_id else f"AVD-UNKNOWN-{len(data)+1}"

                    data.append({
                        "vulnerabilityName": vul_name,
                        "cveId": cve_id,
                        "description": description,
                        "disclosureTime": vul_date,
                        "riskLevel": risk_level,
                        "referenceLink": URL,
                        "affectsWhitelist": 0,
                        "isDelete": 0,
                    })

                except Exception as e:
                    print("parse row error:", e)

        except Exception as e:
            print("request error:", e)
            break

        page += 1

    print(f"COMPLETE. Collected {len(data)} Aliyun AVD advisories.")

    # 数据验证和清理
    try:
        from web_crawler.data_validator import validate_and_clean_vulnerability_data
        data = validate_and_clean_vulnerability_data(data, "avd")
        print(f"Data validation complete. Final count: {len(data)} advisories.")
    except ImportError:
        print("Data validator not available, returning raw data.")

    return data

if __name__ == "__main__":
    # 获取爬到的数据
    data = avd()

    # 打印前三行数据（取前3个字典项）
    print(json.dumps(data[:3], indent=4, ensure_ascii=False))
