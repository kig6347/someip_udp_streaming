import cv2
import numpy as np
from scapy.all import *
import PackageStructure as someip


cv2.namedWindow('img',cv2.WINDOW_NORMAL)
cv2.namedWindow('img',cv2.WINDOW_AUTOSIZE)

a =np.array([],np.uint8)
b =np.array([],np.uint8)
c =np.array([],np.uint8)
d =np.array([],np.uint8)
e =np.array([],np.uint8)
f =np.array([],np.uint8)
g =np.array([],np.uint8)# np.uint8 important
h =np.array([],np.uint8)
i =np.array([],np.uint8)
j =np.array([],np.uint8)
k =np.array([],np.uint8)
l =np.array([],np.uint8)
m =np.array([],np.uint8)
n =np.array([],np.uint8)
o =np.array([],np.uint8)
p =np.array([],np.uint8)

def dul(packet):
    global a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q
    #print('packet=',packet)
    sipPacket = someip.WholePackage(raw(packet[3]))

    img = np.array(list(raw(sipPacket.payload)), dtype=np.uint8)

    print('img[0]',img[0])
    if img[0] == 0 :
        img = np.delete(img,0)
        a = img
    elif img[0] == 1 :
        img = np.delete(img,0)
        b = img
    elif img[0] == 2 :
        img = np.delete(img,0)
        c = img
    elif img[0] == 3 :
        img = np.delete(img,0)
        d = img
    elif img[0] == 4 :
        img = np.delete(img,0)
        e = img
    elif img[0] == 5 :
        img = np.delete(img,0)
        f = img
    elif img[0] == 6 :
        img = np.delete(img,0)
        g = img
    elif img[0] == 7 :
        img = np.delete(img,0)
        h = img
    elif img[0] == 8 :
        img = np.delete(img,0)
        i = img
    elif img[0] == 9 :
        img = np.delete(img,0)
        j = img
    elif img[0] == 10 :
        img = np.delete(img,0)
        k = img
    elif img[0] == 11:
        img = np.delete(img,0)
        l = img
    elif img[0] == 12 :
        img = np.delete(img,0)
        m = img
    elif img[0] == 13 :
        img = np.delete(img,0)
        n = img
    elif img[0] == 14 :
        img = np.delete(img,0)
        o = img
    elif img[0] == 15 :
        img = np.delete(img,0)
        p = img
    b_frame = np.concatenate((a,b,c,d,e,f,g))
    g_frame = np.concatenate((a,b,c,d,e,f,g))
    r_frame = np.concatenate((a,b,c,d,e,f,g))
    b_frame.resize((100,100))
    g_frame.resize((100,100))
    r_frame.resize((100,100))
    frame = cv2.merge((b_frame,g_frame,r_frame))  
    cv2.imshow('img', frame)

    if cv2.waitKey(1)==ord('q'):
        cv2.destroyAllWindows()
        sys.exit()

sniff(count=0,prn=dul,filter="udp port 138")





