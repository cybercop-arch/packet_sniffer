import socket
from scapy.all import *
from scapy.layers.l2 import Ether

sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  #capturing all the frames from the ethernet, at the link layer
#AF specifies the address of the family within the socket so its being used to capture the packets at the link layer
#that sock RAW captures all the raw data on the lower levels of the protocol on the OSI model
# ntohs is the protocol thats gonna convert the numeric value from the network byte over into a host byte so it will represent the ip packets and then we need to convert that


#binding the interface(change this if youre on a VPN), eth0 is the interface we will be using
interface = "eth0"
sniffer_socket.bind((interface, 0))

try:
    while True:
        raw_data, addr = sniffer_socket.recvfrom(65535)            #all ports but we can specify
        packet = Ether(raw_data)
        print(packet.summary())
except KeyboardInterrupt:
     sniffer_socket.close()
