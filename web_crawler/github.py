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
                url = url.replace("page=%d" % (page - 1), "page=%d" % page)

            driver.get(url)
            time.sleep(3)

            table = driver.find_element(By.CLASS_NAME, "Box")

            # data
            rows = table.find_elements(By.CLASS_NAME, "Box-row")
            for row in tqdm(rows, desc=f"Processing page {page} of {page_count} pages"):
                Vuln_ID = row.find_element(By.CLASS_NAME, "text-bold").text
                Summary = row.find_element(By.CLASS_NAME, "Link--primary").text
                Severity = row.find_element(By.CLASS_NAME, "Label").text
                Date = row.find_element(By.TAG_NAME, "relative-time").get_attribute("datetime").split("T")[0]
                URL = row.find_element(By.TAG_NAME, "a").get_attribute("href")
                row_data = [Vuln_ID, Summary, Date, Severity, URL]
                data.append(row_data + [""] * (len(header_names) - len(row_data)))

        return header_names, data

    finally:
        driver.quit()


def github(start_page = 1, page_count = 25):
    print("Gathering security advisories from GitHub...")
    target_url = "https://github.com/advisories?page=1&query=type%3Areviewed"  # 替换为实际目标 URL
    scraped_data_header, scraped_data = scrape_data(target_url, start_page, page_count)
    df = pd.DataFrame(scraped_data)
    df.columns = scraped_data_header
    df.to_csv("github.csv", index=False, encoding="utf-8")
    print("COMPLETE. Data saved to `github.csv`")

if __name__ == "__main__":
    github()
