import cv2
import numpy as np
from scapy.all import *
import PackageStructure as someip

#np.set_printoptions(threshold=np.inf, linewidth=np.inf)
cv2.namedWindow('img',cv2.WINDOW_NORMAL)

b =np.array([])
g =np.array([])
r =np.array([])

def dul(packet):
    print('packet=',packet)

    sipPacket = someip.WholePackage(raw(packet[3]))

    img = np.array(list(raw(sipPacket.payload)), dtype=np.uint8)
    img = np.resize(img,(35,35))
    if img[0][0] == 0 :
        b = img
    elif img[0][0] == 1 :
        g = img
    elif img[0][0] == 2 :
        r = img
        cv2.imshow('img', img)

    #cv2.imshow('img', img)

    if cv2.waitKey(1)==ord('a'):
        cv2.destroyAllWindows()
        sys.exit()

sniff(count=0,prn=dul,filter="udp port 138")


