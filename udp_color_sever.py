from scapy.all import *
from scapy.layers.inet import UDP, TCP, IP
from scapy.layers.l2 import Ether
import PackageStructure as someip
import numpy as np
import cv2

import sys

def MakeSOMEIPPackage():
    package = someip.WholePackage()
    package.msg_id.srv_id = 0xffff
    package.msg_id.sub_id = 0x0
    package.msg_id.method_id = 0x0000

    package.req_id.client_id = 0xdead
    package.req_id.session_id = 0xbeef

    package.msg_type = 0x01
    package.retcode = 0x00

    return package

def MakeEthPackage():

    package = Ether()/IP(src="192.168.0.69",dst="192.168.0.158")/UDP(sport=138,dport=5900)/MakeSOMEIPPackage()  ##com vs com
    return package

cap = cv2.VideoCapture(0)

while True:
    ret, frame = cap.read()
    #frame = cv2.cvtColor(frame,cv2.COLOR_RGB2GRAY)
    frame = cv2.resize(frame,(35,35),interpolation=cv2.INTER_CUBIC)
    b_frame,g_frame,r_frame = cv2.split(frame)

    b = b_frame.flatten()
    b = np.insert(b,0,0)
    g = g_frame.flatten()
    g = np.insert(g,0,1)
    r = r_frame.flatten()
    r = np.insert(r,0,2)


    package10 = MakeEthPackage()
    package11 = MakeEthPackage()
    package12 = MakeEthPackage()

    package10.add_payload(bytes(b))
    package11.add_payload(bytes(g))
    package12.add_payload(bytes(r))
    #sendp(package12, count=1)
    print('package10',package10)
    print('package11', package11)
    print('package12', package12)
    sendp(package10, count=1)
    sendp(package11, count=1)
    sendp(package12, count=1)

    cv2.imshow('frame', frame)
    print('junsoo')
    if cv2.waitKey(0) & 0xFF == ord('q'):
        break

cap.releaese()
cv2.destroyAllWindows()
sys.exit()