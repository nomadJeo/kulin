# Web Crawler Setup

## Install required packages
```bash
pip install -r requirements.txt
```

## Download the chromedriver

Download the chromedriver from the following link: [https://chromedriver.chromium.org/downloads]
(https://chromedriver.chromium.org/downloads). Make sure to download the version that matches your chrome browser version.

## Modify the `config.yaml` file

The `config.yaml` file contains the configuration for the web crawler. The following are the configuration options:

| Option        | Description                                                                     |
|---------------|---------------------------------------------------------------------------------|
| `driver_path` | The path to the chromedriver executable. You can use relative or absolute path. |
| `enable`      | Enable or disable the web crawler to specific website.                          |
| `start_page`  | The start page of the website.                                                  |
| `page_count`  | The number of pages to crawl.                                                   |

A sample configuration is shown below:

```yaml
driver_path: ./chromedriver # Path to the chromedriver

avd:
  enabled: false 
  # currently not support pagination

nvd:
    enabled: true
    start_page: 1 # Start page for the search
    page_count: 5 # Number of pages to search

github:
    enabled: true
    start_page: 1
    page_count: 5
```

## Run the web crawler

To run the web crawler, execute the following command:

```bash
python main.py
```
