import pandas as pd
import json
import random
from VulLibGen.vuldet_utils.nvd_crawler import fetchNVDInfo

def get_file_path(file_name):
    # 填入数据集的位置，直接在对应目录解压 vuldet_multi_dataset.zip 即可
    base_path = 'VulLibGen/vuldet_utils/vuldet_multi_dataset/'
    return f"{base_path}{file_name}"

def filterReferences(references):
    res = set()
    for reference in references:
        if "github.com" in reference:
            parts = reference.split('/')
            if "issues" in parts or "commit" in parts or "pull" in parts:
                repo_index = parts.index("github.com") + 1 if "github.com" in parts else parts.index("www.github.com") + 1
                repo_name = '/'.join(parts[repo_index:repo_index + 2])
                res.add(repo_name)
            if "tag" in parts:
                tag_index = parts.index("tag") + 1
                tag_name = parts[tag_index]
                res.add(tag_name)
        else:
            parts = reference.split('/')
            filtered_parts = [part for part in parts if len(part) < 20 and not part.isdigit()]
            if len(filtered_parts) > 2:
                res.add('/'.join(filtered_parts[1:]))
    return list(res)

def convert_to_compact_format(libraries):
    """
    Convert the original data structure to the compact format.

    Parameters:
        data (dict): Original data structure with CVE identifiers as keys.

    Returns:
        list: Simplified compact format.
    """
    compact_data = []
    print(libraries)
    for library in libraries:
        # print(library)
        ecosystem = library["ecosystem"]
        package_name = library["package_name"]
        version_ranges = []
        # print(library)
        for range_info in library["vulnerable_version_range"]:
            introduced = range_info.get("introduced")
            fixed = range_info.get("fixed")
            last_affected = range_info.get("last_affected")

            if introduced == "*":
                if last_affected:
                    version_range = f"(*, {last_affected}]"
                else:
                    version_range = f"(*, {fixed})"
            elif last_affected:
                version_range = f"[{introduced}, {last_affected}]"
            elif fixed:
                version_range = f"[{introduced}, {fixed})"
            else:
                version_range = f"[{introduced}, {introduced}]"

            version_ranges.append(version_range)

        compact_data.append([ecosystem, package_name, version_ranges])

    return compact_data

def splitData(cveIds):
    # 按照7：3划分数据集
    random.seed(42)
    random.shuffle(cveIds)
    trainSize = int(len(cveIds) * 0.7)
    trainCveIds = cveIds[:trainSize]
    testCveIds = cveIds[trainSize:]
    return trainCveIds, testCveIds


def format(cveId):
    nvdInfo = fetchNVDInfo(cveId)
    print(f'nvdInfo: {nvdInfo}')

    githubRawInfoMap = json.load(open(get_file_path('githubRawInfoMap.json'), 'r'))
    snykRawInfoMap = json.load(open(get_file_path('snykRawInfoMap.json'), 'r'))
    githubInfoMap = json.load(open(get_file_path('githubInfoMap.json'), 'r'))
    gitlabDBMap = json.load(open(get_file_path('gitLabDBMap.json'), 'r'))
    mendMap = json.load(open(get_file_path('mendio_vul.json'), 'r'))

    debianMap = json.load(open(get_file_path('debianMap.json'), 'r'))
    ubuntuMap = json.load(open(get_file_path('ubuntu_cve_data.json'), 'r'))
    springMap = json.load(open(get_file_path('spring_cve_data_modified.json'), 'r'))
    bugzillaMap = json.load(open(get_file_path('bugzilla_cve_data.json'), 'r'))
    goMap = json.load(open(get_file_path('modified_go_cve_go_data.json'), 'r'))
    amazonMap = json.load(open(get_file_path('Amazon_cve_data.json'), 'r'))
    apacheMap = json.load(open(get_file_path('apache_infos.json'), 'r'))
    tomcatMap = json.load(open(get_file_path('tomcat_infos.json'), 'r'))
    jenkinsMap = json.load(open(get_file_path('jenkins_infos.json'), 'r'))
    rubyMap = json.load(open(get_file_path('rubyMap.json'), 'r'))
    rustMap = json.load(open(get_file_path('rustsecMap.json'), 'r'))
    pypiMap = json.load(open(get_file_path('pypaMap.json'), 'r'))

    nvdInfo_descriptions = nvdInfo['descriptions'][0]['value']
    nvdInfo_references = [reference["url"] for reference in nvdInfo['references']]
    nvdInfo_references = list(set(nvdInfo_references))
    nvdInfo_configurations = []
    if 'configurations' in nvdInfo:
        for configuration in nvdInfo['configurations']:
            nodes = configuration['nodes']
            cpeRelated = []
            for node in nodes:
                for key in node:
                    if key == 'cpeMatch':
                        for item in node[key]:
                            copy = item.copy()
                            if 'vulnerable' in copy:
                                del copy['vulnerable']
                            if 'matchCriteriaId' in copy:
                                del copy['matchCriteriaId']
                            if 'criteria' in copy:
                                parts = copy['criteria'].split(':')[3:]
                                del copy['criteria']
                                parts = [part for part in parts if part != '*']
                                copy['CPE'] = ':'.join(parts)
                            cpeRelated.append(copy)
                nvdInfo_configurations.append(cpeRelated)
    nvdInfo_cwe = []
    if 'weaknesses' in nvdInfo:
        for weakness in nvdInfo['weaknesses']:
            nvdInfo_cwe.append(weakness['description'][0]['value'])
    nvdInfo_vulnStatus = nvdInfo['vulnStatus']
    item = {
        "input": f'''<NVD>
[descriptions]: {nvdInfo_descriptions.strip()}
[keyword in reference links]: {filterReferences(nvdInfo_references)}
[CPEs]: {nvdInfo_configurations}'''
    }

    if cveId in githubRawInfoMap and cveId in githubInfoMap:
        keepInfos = []
        for info in githubInfoMap[cveId]:
            githubRaw = githubRawInfoMap[cveId]
            info_data = {
                "vulnerability_record": info,
                "nvd_description": nvdInfo['descriptions'][0]['value'],
                "nvd_references": nvdInfo_references,
                "website_report": githubRaw['description'],
                "website_report_url": githubRaw['references'],
            }
            keepInfos.append(info)
        item["input"] += f'\n  <GitHub Advisory>    \n{keepInfos[:10]}'

    if cveId in gitlabDBMap:
        gitlabDBInfos = gitlabDBMap[cveId]
        keepInfos = []
        for info in gitlabDBInfos:
            info_data = {
                "vulnerability_record": {
                    "ecosystem": info['ecosystem'],
                    "package_name": info['package'],
                    "affected_range": info['affected_range'],
                },
                "nvd_description": nvdInfo['descriptions'][0]['value'],
                "nvd_references": nvdInfo_references,
                "website_report": info['description'],
                "website_report_url": info['urls'],
            }
            keepInfos.append(f'{info["package_slug"]}: {info["affected_range"]}')
        item["input"] += f'\n  <GitLab Advisory>    \n{keepInfos[:10]}'

    if cveId in snykRawInfoMap:
        keepInfos = []
        for info in snykRawInfoMap[cveId]:
            info_data = {
                "vulnerability_record": {
                    "ecosystem": info['ecosystem'],
                    "package_name": info['package_name'],
                    "vulnerable_version_range": info['vulnerable_version_range'],
                },
                "nvd_description": nvdInfo['descriptions'][0]['value'],
                "nvd_references": nvdInfo_references,
                "website_report": info['Overview'] if 'Overview' in info else info['NVD Description'],
                "website_report_url": [ref['link'] for ref in info['references']],
            }
            keepInfos.append(f'{info["ecosystem"]} {info["package_name"]}: {info["vulnerable_version_range"]}')
        item["input"] += f'\n  <Snyk>\n    {keepInfos[:10]}'

    if cveId in mendMap and mendMap[cveId]['top_fix_detail'] != 'None':
        info_data = {
            "vulnerability_record": {
                "language": mendMap[cveId]["language"],
                "top_fix_detail": mendMap[cveId]["top_fix_detail"]
            },
            "nvd_description": nvdInfo['descriptions'][0]['value'],
            "nvd_references": nvdInfo_references,
            "website_report": mendMap[cveId]['description'],
            "website_report_url": mendMap[cveId]['references'],
        }
        item["input"] += f'\n  <Mend.io>\n    {mendMap[cveId]["language"]}:{mendMap[cveId]["top_fix_detail"]}'

    if cveId in apacheMap:
        apacheInfos = apacheMap[cveId]
        refinementInfos = []
        for info in apacheInfos:
            refinementInfos.append(info)
        item["input"] += f'\n  <Apache>\n    {".".join(refinementInfos)}'

    if cveId in tomcatMap:
        item["input"] += f'\n  <Tomcat>\n    {tomcatMap[cveId]["related_paragraphs"]}'

    if cveId in jenkinsMap:
        item["input"] += f'\n  <Jenkins>\n    {jenkinsMap[cveId]["related_paragraphs"]}'

    if cveId in debianMap:
        item["input"] += f'\n  <Debian>\n    {debianMap[cveId][:10]}'

    if cveId in ubuntuMap:
        packages = ubuntuMap[cveId]['packages']
        filteredInfos = []
        for package in packages:
            filteredInfos.append(f'{package["name"]}')
        if len(filteredInfos) > 0:
            item["input"] += f'\n  <Ubuntu>\n    {filteredInfos}'

    if cveId in springMap:
        springInfos = springMap[cveId]
        filteredInfos = []
        for info in springInfos:
            filteredInfos.append(f'{info["package_name"]}: {info["vulnerable_version_range"]}')
        item["input"] += f'\n  <Spring>\n    {filteredInfos}'

    if cveId in bugzillaMap:
        desc = bugzillaMap[cveId][0]['description']
        product = bugzillaMap[cveId][0]['product']
        versions = bugzillaMap[cveId][0]['version']
        item[
            "input"] += f'\n  <Bugzilla>\n    decription: {desc}\n     version: {versions}\n     product: {product}'

    if cveId in goMap:
        item["input"] += f'\n  <Go>\n    {goMap[cveId]}'

    if cveId in amazonMap:
        item["input"] += f'\n  <Amazon>\n    {amazonMap[cveId]}'

    if cveId in rubyMap:
        item["input"] += f'\n  <Ruby>\n    {rubyMap[cveId]}'

    if cveId in pypiMap:
        item["input"] += f'\n  <PyPi>\n    {pypiMap[cveId]}'

    if cveId in rustMap:
        item["input"] += f'\n  <RustSec>\n    {rustMap[cveId]}'

    return item