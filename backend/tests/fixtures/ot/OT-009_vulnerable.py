import requests


def read_meter(url):
    return requests.get(url, verify=False, timeout=5).json()
