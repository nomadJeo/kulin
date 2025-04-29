import time
import requests
import json
import pandas
import logging
import tqdm
import random

BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='
API_KEY= '4bc5f3aa-e422-41d3-a1a4-bc9881eefad3'
headers = {
    'apiKey': f'{API_KEY}'
}

def fetchNVDInfo(cveId):
    url = f'{BASE_URL}{cveId}'
    retries = 3
    for _ in range(retries):
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                nvdInfo = response.json()
                if len(nvdInfo['vulnerabilities']) == 1:
                    return nvdInfo['vulnerabilities'][0]['cve']
                elif len(nvdInfo['vulnerabilities']) == 0:
                    logging.error(f"{cveId} Error: No vulnerabilities found.")
                    return None
                else:
                    logging.error(f"{cveId} Error: Multiple vulnerabilities found.")
                    return None
            elif response.status_code == 403:
                logging.error(f"{cveId} Error 403: Access forbidden. Retrying after delay.")
                time.sleep(random.randint(5, 10))
            else:
                logging.error(f"{cveId} Error: {response.text}")
                time.sleep(6)
        except requests.exceptions.RequestException as e:
            logging.error(f"{cveId} RequestException: {e}")
            time.sleep(6)
            continue
    return None