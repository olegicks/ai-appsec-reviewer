import paramiko


def reboot_rtu(host, key_path):
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.connect(host, username="maint", key_filename=key_path, timeout=5)
    ssh.exec_command("reboot")
