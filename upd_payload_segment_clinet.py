import cv2
import numpy as np
from scapy.all import *
import PackageStructure as someip

#np.set_printoptions(threshold=np.inf, linewidth=np.inf)
cv2.namedWindow('img',cv2.WINDOW_NORMAL)
cv2.namedWindow('img',cv2.WINDOW_AUTOSIZE)

b =np.array([],np.uint8)
g =np.array([],np.uint8)
r =np.array([],np.uint8)# np.uint8 important

def dul(packet):
    global g,b,r
    #print('packet=',packet)
    sipPacket = someip.WholePackage(raw(packet[3]))

    img = np.array(list(raw(sipPacket.payload)), dtype=np.uint8)

    print('img[0]',img[0])
    if img[0] == 0 :
        img = np.delete(img,0)
        b = img
    elif img[0] == 1 :
        img = np.delete(img,0)
        g = img
    elif img[0] == 2 :
        img = np.delete(img,0)
        r = img
    frame = np.concatenate((b,g,r))
    frame.resize((53,54))
    cv2.imshow('img', frame)

    if cv2.waitKey(1)==ord('q'):
        cv2.destroyAllWindows()
        sys.exit()

sniff(count=0,prn=dul,filter="udp port 138")





