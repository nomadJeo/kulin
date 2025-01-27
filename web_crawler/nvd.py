from datetime import datetime

import yaml
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import time
import pandas as pd
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
    header_names = ['Vuln. ID', 'Summary', 'Date', 'Severity', 'Ref. URL']
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
                row_data = [Vuln_ID, Summary, Date, Severity, URL]
                data.append(row_data + [""] * (len(header_names) - len(row_data)))

        return header_names, data

    finally:
        driver.quit()

def nvd(start_page = 1, page_count = 20):
    print("Gathering security advisories from NVD...")
    target_url = "https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&results_type=overview&form_type=Basic&search_type=all&startIndex=0"  # 替换为实际目标 URL
    scraped_data_header, scraped_data = scrape_data(target_url, start_page, page_count)
    df = pd.DataFrame(scraped_data)
    df.columns = scraped_data_header
    df.to_csv("nvd.csv", index=False, encoding="utf-8")
    print("COMPLETE. Data saved to `nvd.csv`")

if __name__ == "__main__":
    nvd()
