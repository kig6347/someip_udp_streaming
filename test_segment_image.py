from scapy.all import *
from scapy.layers.inet import UDP, TCP, IP
from scapy.layers.l2 import Ether
import PackageStructure as someip
import numpy as np
import cv2

import sys

cap = cv2.VideoCapture(0)
ext = 7
cv2.namedWindow('img',cv2.WINDOW_NORMAL)
cv2.namedWindow('img',cv2.WINDOW_AUTOSIZE)
cv2.namedWindow('img1',cv2.WINDOW_NORMAL)
cv2.namedWindow('img1',cv2.WINDOW_AUTOSIZE)
while True:
    ret, frame = cap.read()
    frame = cv2.cvtColor(frame,cv2.COLOR_RGB2GRAY)
    frame = cv2.resize(frame,(100,100),interpolation=cv2.INTER_CUBIC)

    frame_flatten = frame.reshape(-1) # flatten , reshape, ravel 중 flatten 은 값복사가 이루어져 메모리가 불안하다.
    a = np.array_split(frame_flatten, ext)

    #print(len(a[0]),len(a[1]))

    for i in range(ext):
        a[i] = np.insert(a[i],0,i)
        time.sleep(0.01)

    for j in range(ext):
        a[j] = np.delete(a[j],0)

    frame1 = np.concatenate((a[0],a[1],a[2],a[3],a[4],a[5],a[6]))
    frame1.resize((100,100))

    cv2.imshow('img', frame1)
    cv2.imshow('img1', frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.releaese()
cv2.destroyAllWindows()
sys.exit()