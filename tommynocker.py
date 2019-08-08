#---------------------------------------------------------
# Poject Name: TommyKnocker 1.0
# WTF???       Portscanner
# Author:      Jurafox
# Created:     25/07/2019
# License:     Free to have fun!
# Copyright:   (c) Jurafox 2019
# Version:     1.0
#---------------------------------------------------------

import socket
import subprocess
import sys
from datetime import datetime


target = input ("Target Adress: ")
targetIp = socket.gethostbyname(target)
tstart = datetime.now()

   

try:
    for p in range(1, 45000):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        res = sock.connect_ex((target, p))
        if res == 0:           
           print("Port:" + str(p))
    sock.close()
    
except Exception:
        print("There was an error.")
        sys.exit()    
              
