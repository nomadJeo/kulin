from selenium import webdriver
from bs4 import BeautifulSoup
import time

from triton.runtime import driver

# 设置Chrome WebDriver
driver = webdriver.Edge()

# 访问页面
url = "https://github.com/advisories?query=type%3Areviewed&page=1"
driver.get(url)

# 等待页面加载和JavaScript执行
time.sleep(5)  # 等待5秒，根据实际页面的加载时间来调整

# 获取页面源代码
html_content = driver.page_source

# 使用BeautifulSoup解析渲染后的HTML
soup = BeautifulSoup(html_content, "html.parser")
print(soup.prettify())

# 关闭浏览器
driver.quit()
