from scapy.all import *
import PackageStructure as someip
def dul(packet):
    print((packet[3]))
    sipPacket = someip.WholePackage(raw(packet[3]))
    '''
    print('sipPacket.msg_id',sipPacket.msg_id)
    print('sipPacket.msg_id.srv_id', sipPacket.msg_id.srv_id)
    print('sipPacket.msg_id.method_id', sipPacket.msg_id.method_id)
    print('sipPacket.len', sipPacket.len)
    print('sipPacket.req_id.client_id', sipPacket.req_id.client_id)
    print('sipPacket.req_id.session_id', sipPacket.req_id.session_id)
    print('sipPacket.payload', sipPacket.payload)
    '''
    payload = raw(sipPacket.payload)
    print('payload',payload)
    '''
    print('payload[3]', payload[3])
    print('payload', type[payload])
    '''
    print('payload', payload)
    print('payload', payload[1])
    print('payload[1]', payload[2])
    print('payload[3]', payload[3])


    if sipPacket.msg_id.srv_id == 0xffff:
        print("----------------------recv")

sniff(count=0,prn=dul,filter="udp port 138")