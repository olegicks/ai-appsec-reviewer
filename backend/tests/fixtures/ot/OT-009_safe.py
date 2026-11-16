import requests


def read_meter(url):
    return requests.get(url, verify="/etc/grid/ca.pem", timeout=5).json()
