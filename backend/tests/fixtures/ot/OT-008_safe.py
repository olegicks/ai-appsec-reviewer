import os
from ftplib import FTP_TLS


def fetch_logs(host):
    ftp = FTP_TLS(host, timeout=10)
    ftp.login(os.environ["RTU_USER"], os.environ["RTU_PASSWORD"])
    return ftp.nlst()
