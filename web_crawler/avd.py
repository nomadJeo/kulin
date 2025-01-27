# 目前只能爬 https://avd.aliyun.com 的数据
# https://avd.aliyun.com/high-risk/list 这类列表的数据暂时爬不到
import yaml
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import pandas as pd
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from tqdm import tqdm

def get_driver_path():
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    return config["driver_path"]

def init_chrome_options():
    chrome_options = Options()

    # Basic settings
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    # chrome_options.add_argument("--window-size=1920x1080")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("enable-logging")
    chrome_options.add_argument("--v=1")
    chrome_options.add_argument("--auto-open-devtools-for-tabs")

    # Geolocation settings
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
    chrome_options.add_experimental_option("prefs", {"profile.default_content_setting_values.geolocation": 1})

    return chrome_options


def scrape_data(url):
    chrome_options = init_chrome_options()
    driver_path = get_driver_path()
    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)

    try:
        # url = get_true_url(url)
        driver.get(url)

        table = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.CLASS_NAME, "table"))
        )
        tbody = table.find_element(By.TAG_NAME, "tbody")

        # header
        header_names = ['Vuln. ID', 'Summary', 'Date', 'Severity', 'Ref. URL']

        # data
        data = []
        rows = tbody.find_elements(By.TAG_NAME, "tr")
        for row in tqdm(rows):
            cells = row.find_elements(By.TAG_NAME, "td")
            row_data = [[cell.text for cell in cells][0], [cell.text for cell in cells][1], [cell.text for cell in cells][3], [cell.text for cell in cells][4], row.find_element(By.TAG_NAME, "a").get_attribute("href")]
            data.append(row_data + [""] * (len(header_names) - len(row_data)))

        return header_names, data

    finally:
        driver.quit()


def get_true_url(url):
    chrome_options = init_chrome_options()
    driver_path = "./chromedriver"
    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    while True:
        try:
            driver.get(url)
            true_url = driver.current_url
            driver.quit()
            if true_url == url:
                raise Exception
            print("true_url: ", true_url)
            return true_url

        except Exception:
            continue

def avd(start_page = 1, page_count = 20):
    print("Gathering security advisories from Aliyun...")
    target_url = "https://avd.aliyun.com"
    scraped_data_header, scraped_data = scrape_data(target_url)
    df = pd.DataFrame(scraped_data)
    df.columns = scraped_data_header
    df.to_csv("avd.csv", index=False, encoding="utf-8")
    print("COMPLETE. Data saved to `avd.csv`")


if __name__ == "__main__":
    avd()
