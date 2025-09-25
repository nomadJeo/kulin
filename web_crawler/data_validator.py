"""
漏洞数据验证和清理工具
统一处理GitHub、AVD、NVD爬虫的数据质量问题
"""

import re
from datetime import datetime
from typing import List, Dict, Any


def validate_and_clean_vulnerability_data(data: List[Dict[str, Any]], source: str = "unknown") -> List[Dict[str, Any]]:
    """
    验证和清理漏洞数据

    Args:
        data: 漏洞数据列表
        source: 数据源标识 (github, avd, nvd)

    Returns:
        清理后的漏洞数据列表
    """
    cleaned_data = []

    for item in data:
        cleaned_item = clean_single_vulnerability(item, source)
        if cleaned_item:  # 只保留有效数据
            cleaned_data.append(cleaned_item)

    return cleaned_data


def clean_single_vulnerability(item: Dict[str, Any], source: str) -> Dict[str, Any]:
    """清理单个漏洞数据"""
    try:
        cleaned = {}

        # 1. 清理漏洞名称
        cleaned['vulnerabilityName'] = clean_vulnerability_name(
            item.get('vulnerabilityName', ''),
            item.get('cveId', ''),
            source
        )

        # 2. 清理CVE ID
        cleaned['cveId'] = clean_cve_id(item.get('cveId', ''), source)

        # 3. 清理披露时间
        cleaned['disclosureTime'] = clean_disclosure_time(item.get('disclosureTime', ''))

        # 4. 清理描述
        cleaned['description'] = clean_description(
            item.get('description', ''),
            cleaned['vulnerabilityName'],
            source
        )

        # 5. 清理风险等级
        cleaned['riskLevel'] = clean_risk_level(item.get('riskLevel', ''))

        # 6. 清理参考链接
        cleaned['referenceLink'] = clean_reference_link(item.get('referenceLink', ''))

        # 7. 保持固定字段
        cleaned['affectsWhitelist'] = 0
        cleaned['isDelete'] = 0

        return cleaned

    except Exception as e:
        print(f"清理漏洞数据时出错: {e}")
        return None


def clean_vulnerability_name(name: str, cve_id: str, source: str) -> str:
    """清理漏洞名称"""
    if not name or name.strip() == '':
        # 如果没有名称，根据CVE ID生成一个
        if cve_id:
            return f"{source.upper()} Vulnerability {cve_id}"
        else:
            return f"{source.upper()} 未知漏洞"

    name = str(name).strip()

    # 限制长度
    if len(name) > 200:
        name = name[:197] + "..."

    # 清理特殊字符
    name = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', name)  # 移除控制字符

    return name


def clean_cve_id(cve_id: str, source: str) -> str:
    """清理CVE ID"""
    if not cve_id or str(cve_id).strip() == '':
        # 生成一个默认CVE ID
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"{source.upper()}-{timestamp}"

    cve_id = str(cve_id).strip()

    # 验证CVE格式
    if re.match(r'^CVE-\d{4}-\d+$', cve_id):
        return cve_id
    elif re.match(r'^AVD-\d{4}-\d+$', cve_id):
        return cve_id
    else:
        # 如果不是标准格式，保持原样但确保不为空
        return cve_id if cve_id else f"{source.upper()}-UNKNOWN"


def clean_disclosure_time(date_str: str) -> str:
    """清理披露时间"""
    if not date_str or str(date_str).strip() == '':
        return datetime.now().strftime("%Y-%m-%d")

    date_str = str(date_str).strip()

    # 验证日期格式
    try:
        # 尝试解析YYYY-MM-DD格式
        datetime.strptime(date_str, "%Y-%m-%d")
        return date_str
    except ValueError:
        # 如果格式不对，返回当前日期
        return datetime.now().strftime("%Y-%m-%d")


def clean_description(desc: str, vuln_name: str, source: str) -> str:
    """清理描述"""
    if not desc or str(desc).strip() == '':
        # 如果没有描述，生成一个基本描述
        return f"{source.upper()}漏洞库收录的漏洞：{vuln_name}"

    desc = str(desc).strip()

    # 限制长度
    if len(desc) > 1000:
        desc = desc[:997] + "..."

    # 清理特殊字符
    desc = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', desc)  # 移除控制字符

    return desc


def clean_risk_level(risk: str) -> str:
    """清理风险等级"""
    if not risk or str(risk).strip() == '':
        return "Medium"

    risk = str(risk).strip().title()

    # 标准化风险等级
    risk_mapping = {
        'Critical': 'High',
        'Moderate': 'Medium',
        'Info': 'Low',
        'Information': 'Low',
        'Informational': 'Low'
    }

    risk = risk_mapping.get(risk, risk)

    # 只允许标准值
    if risk in ['High', 'Medium', 'Low']:
        return risk
    else:
        return 'Medium'  # 默认中等风险


def clean_reference_link(link: str) -> str:
    """清理参考链接"""
    if not link or str(link).strip() == '':
        return "https://example.com"

    link = str(link).strip()

    # 验证URL格式
    if not link.startswith(('http://', 'https://')):
        link = 'https://' + link

    return link