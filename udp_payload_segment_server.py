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
ext = 7
cv2.namedWindow('img',cv2.WINDOW_NORMAL)
cv2.namedWindow('img',cv2.WINDOW_AUTOSIZE)
while True:
    ret, frame = cap.read()
    frame = cv2.cvtColor(frame,cv2.COLOR_RGB2GRAY)
    frame = cv2.resize(frame,(100,100),interpolation=cv2.INTER_CUBIC)

    frame_flatten = frame.reshape(-1) # flatten , reshape, ravel 중 flatten 은 값복사가 이루어져 메모리가 불안하다.
    a = np.array_split(frame_flatten, ext)

    #print(len(a[0]),len(a[1]))

    for i in range(ext):
        a[i] = np.insert(a[i],0,i)
        print('i',len(a[i]))
        package10 = MakeEthPackage()
        package10.add_payload(bytes(a[i]))
        sendp(package10, count=1)
        time.sleep(0.01)


    cv2.imshow('img', frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.releaese()
cv2.destroyAllWindows()
sys.exit()