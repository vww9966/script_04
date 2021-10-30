#! /usr/bin/python3
# Vaughn Woerpel
# NSSA 221
# Script 04 - ATTACKER REPORT
# 10 October 2021

import os
from geoip import geolite2
from datetime import date
import re

class BadRequest:
    def __init__(self, src):
        self.src = src
        self.ctry = "CHINA!"
        self.count = 0;

    def inc_req_num(self):
        self.count = self.count+1

def scan_file(fname):
    global requests
    requests = []
    file = open(fname, "r")
    for line in file:
        if "Failed password" in line:
            inc = False
            match = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",line)
            for req in requests:
                if req.src == match[0]:
                    req.inc_req_num()
                    inc = True
            if inc:
                continue
            req = BadRequest(match[0])
            requests.append(req)


print("Attacker Report - ", date.today())
scan_file("syslog.log")

for req in requests:
    print(str(req.count) + "\t\t" + req.src + "\t\t" + req.ctry)
