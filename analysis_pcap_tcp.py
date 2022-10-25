# Naseeba Faiza
# CSE310 Networks Programming Assignment 2
import socket
from collections import Counter
#import dpkt

class Packet():
    def __init__(self, packetInp):
        self.timestamp  = packetInp[0]
        self.raw_data = packetInp[1]
        packetRaw = packetInp[1]
        self.ethernetDest = packetRaw[:6]
        self.ethernetSrc = packetRaw[6:12]
        self.ethernetType = packetRaw[12:14]
        self.ipLength = int.from_bytes(packetRaw[16:18], byteorder = 'big')
        self.ipSrc = packetRaw[26:30]
        self.ipDest = packetRaw[30:34]
        self.tcpSrcPort = int.from_bytes(packetRaw[34:36], byteorder= 'big')
        self.tcpDestPort = int.from_bytes(packetRaw[36:38], byteorder= 'big')
        self.tcpSeqNum = int.from_bytes(packetRaw[38:42], byteorder= 'big')
        self.tcpACKNum = int.from_bytes(packetRaw[42:46], byteorder= 'big')
        self.tcpHeaderLength = 4*(int.from_bytes(packetRaw[46:47], byteorder= 'big') >>4)
        self.all_flags = int.from_bytes(packetRaw[47:48], byteorder= 'big')
        self.mss = int.from_bytes(packetRaw[56:58], byteorder= 'big')
        self.tcp_flag_fin = self.all_flags&1
        self.all_flags = self.all_flags>>1
        self.syn = self.all_flags&1
        self.all_flags = self.all_flags>>1
        self.tcp_flag_rst = self.all_flags&1
        self.all_flags = self.all_flags>>1
        self.tcp_flag_psh = self.all_flags&1
        self.all_flags = self.all_flags>>1
        self.ack = self.all_flags&1
        self.all_flags = self.all_flags>>1
        self.tcp_flag_urg = self.all_flags&1
        self.all_flags = self.all_flags>>1
        self.tcp_flag_ecn = self.all_flags&1
        self.all_flags = self.all_flags>>1
        self.tcp_flag_cwr = self.all_flags&1
        self.all_flags = self.all_flags>>1
        self.tcp_flag_non = self.all_flags&1
        self.tcpPayload = packetRaw[34+self.tcpHeaderLength:]
        self.tcpPayloadLength = len(self.tcpPayload)
        self.receiveWin = int.from_bytes(packetRaw[48:50], byteorder = 'big')


  


