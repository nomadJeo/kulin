from avd import avd
from github import github
from nvd import nvd

import yaml

def analyze_config():
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    return config


def main():
    try:
        config = analyze_config()
        if config is None:
            raise Exception("Failed to load configuration file")
        if config["avd"]["enabled"]:
            avd()
        if config["nvd"]["enabled"]:
            nvd(config["nvd"]["start_page"], config["nvd"]["page_count"])
        if config["github"]["enabled"]:
            github(config["github"]["start_page"], config["github"]["page_count"])
    except Exception as e:
        print("Exception occurred：", e)

    finally:
        print("All tasks completed.")


if __name__ == '__main__':
    main()