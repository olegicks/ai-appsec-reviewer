from ftplib import FTP_TLS


def fetch_logs(host):
    ftp = FTP_TLS(host, timeout=10)
    ftp.login("admin", "admin")
    return ftp.nlst()
