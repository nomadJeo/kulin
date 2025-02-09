from datetime import datetime

import yaml
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import time
from tqdm import tqdm

def get_driver_path():
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    return config["driver_path"]


def scrape_data(url, start_page, page_count):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920x1080")
    driver_path = get_driver_path()
    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)

    data = []
    try:
        for page in range(start_page, start_page + page_count):
            if page > 1:
                url = url.replace("startIndex=%d" % ((page - 2) * 20), "startIndex=%d" % ((page - 1) * 20))

            driver.get(url)
            time.sleep(3)

            table = driver.find_element(By.CLASS_NAME, "table")
            tbody = table.find_element(By.TAG_NAME, "tbody")

            rows = tbody.find_elements(By.TAG_NAME, "tr")
            for row in tqdm(rows, desc=f"Processing page {page} of {page_count} pages"):
                cells = row.find_elements(By.TAG_NAME, "td")
                Vuln_ID = row.find_element(By.TAG_NAME, "a").text
                Summary = cells[0].find_element(By.TAG_NAME, "p").text
                Date = cells[0].find_element(By.TAG_NAME, "span").text
                dt = datetime.strptime(Date, "%B %d, %Y; %I:%M:%S %p %z")
                Date = dt.strftime("%Y-%-m-%-d")
                Severity = cells[1].text
                URL = row.find_element(By.TAG_NAME, "a").get_attribute("href")
                data.append({
                "vulnerabilityName": Vuln_ID,
                "disclosureTime": Date,
                "riskLevel": Severity,
                "referenceLink": URL,
                "affectsWhitelist":0
            })
        return data


    finally:
        driver.quit()

def nvd(start_page = 1, page_count = 200):
    print("Gathering security advisories from NVD...")
    target_url = "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&results_type=overview&form_type=Basic&search_type=all&startIndex=0"  # 替换为实际目标 URL
    scraped_data = scrape_data(target_url, start_page, page_count)
    print(scraped_data)
    return scraped_data

if __name__ == "__main__":
    nvd()
