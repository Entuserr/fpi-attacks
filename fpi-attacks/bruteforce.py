import collections
import re
import sys
import time
from os import listdir
from os.path import join, isdir, isfile

import pyshark
from scapy.compat import raw
from scapy.layers.inet import TCP
from scapy.packet import ls
from scapy.utils import rdpcap


def perform(packets, shark):
    ftp_logins = []
    http_logins = []
    ssh_logins = []
    smb_logins = []
    telnet_logins = []
    for i, sh in enumerate(shark):
        if hasattr(sh,'smb') and len(telnet_logins) == 0 and len(ssh_logins) == 0:
            if sh.smb.flags.int_value != 88:
                smb_logins.append(i + 1)
        elif hasattr(sh,'telnet') and len(smb_logins) == 0 and len(ssh_logins) == 0:
            if int(sh.__dict__['length']) != 68:
                if '' in sh.telnet.__dict__['_all_fields']:
                    info = sh.telnet.__dict__['_all_fields']['']
                    if info != 'Do Authentication Option' and info != 'Will Linemode' and info != 'Don\'t Linemode':
                        telnet_logins.append(i+1)
                if 'telnet.data' in sh.telnet.__dict__['_all_fields']:
                    telnet_data = sh.telnet.__dict__['_all_fields']['telnet.data']
                    if re.search(r'Welcome',telnet_data) is None and re.search(r'\\xa', telnet_data) is None:
                        telnet_logins.append(i + 1)
        elif hasattr(sh,'ssh') and len(smb_logins) == 0 and len(telnet_logins) == 0:
            lenght = int(sh.__dict__['length'])
            if lenght > 100 or lenght == 86 or lenght == 114 or lenght == 82:
                if lenght != 1146 and lenght != 346 and int(sh.tcp.srcport) != 22:
                    ssh_logins.append(i+1)
    if len(smb_logins) < 5:
        for i, p in enumerate(packets):
            if p.haslayer(TCP):
                r = raw(p)
                indices = []
                if r.find("login.php".encode("cp1251")) != -1 and r.find("&password".encode("cp1251")) != -1:
                    http_logins.append(i + 1)

                if r.find("USER ".encode("cp1251")) != -1:
                    if len(re.findall(r'\w+', p.load.decode("cp1251"))) > 1:
                        user = (re.findall(r'\w+', p.load.decode("cp1251"))[1])
                        indices.append(i + 1)
                        n = 0
                        for j in range(i, len(packets)):
                            rw = raw(packets[j])
                            if rw.find("PASS ".encode("cp1251")) != -1 or rw.find("QUIT".encode("cp1251")) != -1:
                                indices.append(j + 1)
                                n += 1
                            if (n > 1):
                                break
                        dict = {'user': user}
                        dict.update({'packets': indices})
                        ftp_logins.append(dict)

    users = set()
    ind = []
    vuln = ""
    score = 0.0
    if len(ftp_logins) > 0:
        for l in ftp_logins:
            if l.get('user') in users:
                score = 1.0
                ind.extend(l.get('packets'))
                vuln = "Bruteforce FTP"
            else:
                users.add(l.get('user'))
                ind = l.get('packets')

    if len(http_logins) > 0:
        score = 1.0
        ind = http_logins
        vuln = "Bruteforce HTTP"
    elif len(smb_logins) > 0:
        score = 1.0
        ind = smb_logins
        vuln = "Bruteforce SMB"

    if len(ssh_logins) > 0:
        score = 1.0
        ind = ssh_logins
        vuln = "Bruteforce SSH"

    if len(telnet_logins) > 0:
        score = 1.0
        ind = telnet_logins
        vuln = "Bruteforce Telnet"

    return (score, ind, 4, vuln)
