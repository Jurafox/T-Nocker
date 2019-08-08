#---------------------------------------------------------
# Poject Name: TommyKnocker 1.0
# WTF???       Portscanner
# Author:      Jurafox
# Created:     204/08/2019
# License:     Free to have fun!
# Copyright:   (c) Jurafox 2019
# Version:     1.1
#---------------------------------------------------------

# Importing Modules
import socket,subprocess,sys,time, os
from datetime import datetime


# Scan input
target = input ("Enter a remote host to scan: ")
targetIp = socket.gethostbyname(target)
startport = input ("From Port > ")
endport = input ("To Port > ")
tstart = datetime.now()


# Portscan Engine   
def portscan():

    for p in range(int(startport),int(endport)+1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            res = sock.connect_ex((target, p))
            if res == 0:           
                print("Open Port:" + str(p))   
                sock.close()
            
        except Exception:
            print("There was an error.")
            #sys.exit()

# Time start 
t1 = datetime.now()

# Scan run
portscan()

# Time end
t2 = datetime.now()

# Diff start/end time
ztotal = t2 - t1

# Scaninfo
print("\nScan complete\n")
time.sleep(2)
print("Scan time: " + str(ztotal))

newscan = input("\nDo you want a new scan? [y/n] > ")
if str(newscan) == str("y"):
    
    # Start Program new (Only Terminal)
    restart = sys.executable
    os.execl(restart, restart, * sys.argv)
else:
    print("\nProgramm close...")
    time.sleep(5)
    
    sys.exit(0)
            
              
