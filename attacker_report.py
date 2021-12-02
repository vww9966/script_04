#! /usr/bin/python3
# Vaughn Woerpel
# NSSA 221
# Script 04 - ATTACKER REPORT
# 10 October 2021
# Testline

import os
from os import system
from datetime import date
import re
from geoip import geolite2

#BadRequest class to hold the source, sets the country to the ip geolocation, and increments count. This is so that the data is far easier to handle
class BadRequest:
    #Initiates the class with ip and count = 1, and sets the country
    def __init__(self, src):
        self.src = src
        #Tries to get the country, if it fails defaults to US
        try:
            self.country = geolite2.lookup(src).country
        except:
            self.country = "US"
        self.count = 1;

    #Increments the count of the requests
    def inc_req_num(self):
        self.count = self.count+1

#Bubble sorts to organize by ascending order of requests
def bubble_sort(arr):
    #Loops along range of array
    for i in range(len(arr)):
        #Loops along range of array - 1, so that arr[x+1] does not go over the range of the array
        for x in range(len(arr)-1):
            #Checks if the number of requests in one location is greater than location + 1 and then swaps
            if arr[x].count > arr[x+1].count:
                arr[x], arr[x+1] = arr[x+1], arr[x]

#Scans through the file of requests
def scan_file(fname):
    #Sets a global variable for the request list that holds elements of BadRequests
    global requests
    requests = []
    #Opens the file in read mode and loops along it line by line
    file = open(fname, "r")
    for line in file:
        #Checks if password failed
        if "Failed password" in line:
            inc = False
            #Does a regex match to get the ip from the line
            match = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",line)
            #Checks to see if the ip is already in the requests list. If it is not, add it. If it is, increment it.
            for req in requests:
                if req.src == match[0]:
                    req.inc_req_num()
                    inc = True
            #Continues if it's only incremented
            if inc:
                continue
            req = BadRequest(match[0])
            requests.append(req)


#Main display section. Clears the console, prints attacker report + the date, puts column headers.
#os.system("clear")
print("Attacker Report - ", date.today())
print("\nCOUNT\t\tIP ADDRESS\t\tCOUNTRY")

#Scans the file and adds to global requests
scan_file("syslog.log")

#Sorts the requests by number of requests each
bubble_sort(requests)

#Prints each request greater than 10
for req in requests:
    if(req.count > 10):
        print(str(req.count) + "\t\t" + req.src + "\t\t" + req.country)
