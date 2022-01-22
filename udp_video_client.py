import cv2
import numpy as np
from scapy.all import *
import PackageStructure as someip

#np.set_printoptions(threshold=np.inf, linewidth=np.inf)
capture = cv2.VideoCapture(0)
cv2.namedWindow('img',cv2.WINDOW_NORMAL)
def dul(packet):
    print('packet=',packet)

    sipPacket = someip.WholePackage(raw(packet[3]))

    img = np.array(list(raw(sipPacket.payload)), dtype=np.uint8)
    img = np.resize(img,(35,35))

    cv2.imshow('img', img)

    if cv2.waitKey(1)==ord('a'):
        capture.release()
        cv2.destroyAllWindows()
        sys.exit()

sniff(count=0,prn=dul,filter="udp port 138")


