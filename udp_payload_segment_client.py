import cv2
import numpy as np
from scapy.all import *
import PackageStructure as someip

#np.set_printoptions(threshold=np.inf, linewidth=np.inf)
cv2.namedWindow('img',cv2.WINDOW_NORMAL)

b =np.zeros([],np.uint8)
g =np.zeros([],np.uint8)
r =np.zeros([],np.uint8)# np.uint8 important

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

    frame = np.concatenate((b,g))
    frame.resize((54,53))
    img = np.resize(frame,(35,35))
    cv2.imshow('img', img)


    if cv2.waitKey(1)==ord('q'):
        cv2.destroyAllWindows()
        sys.exit()

sniff(count=0,prn=dul,filter="udp port 138")




