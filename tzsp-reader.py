import socket
import struct
import binascii
from struct import *

UDP_IP = "0.0.0.0"
UDP_PORT = 37008 

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind((UDP_IP,UDP_PORT))

def getType(typeData):
	types = {
		0:"Received tag list",
		1:"Packet for transmit",
		2:"Reserved",
		3:"Configuration",
		4:"Keepalive",
		5:"port opener"
	}
	return types[typeData]

def getProtocol(typeData):
	types = {
		0x01:"Ethernet",
		0x12:"IEE 802.11",
		0x77:"Prism Header",
		0x7F:"WLAN AVS"
	}
	return types[typeData]

def getTagType(type):
	types = {
		0x00: "TAG_PADDING",
		0x01: "TAG_END",
		0x0A: "TAG_RAW_RSSI",
		0x0B: "TAG_SNR",
		0x0C: "TAG_DATA_RATE",
		0x0D: "TAG_TIMESTAMP",
		0X0F: "TAG_CONTENTION_FREE",
		0X10: "TAG_DECRYPTED",
		0X11: "TAG_FCS_ERROR",
		0X12: "TAG_RX_CHANNEL",
		0X28: "TAG_PACKET_COUNT",
		0X29: "TAG_RX_FRAME_LENGTH",
		0X3C: "TAG_WLAN_RADIO_HDR_SERIAL"
	}
	return types[type]

def processTag(tag):
	tagType = getTagType(ord(tag[0]))
	tagLength = 0
	if(tagType not in ["TAG_END","TAG_PADDING"]):
		tagLength = ord(tag[1])
	print "tag type: %r" % tagType
	print "tag length: %r" % tagLength
	
while True:
	data, addr = sock.recvfrom(1024)

	headers = data[0:4]
	tags = data[4:]

	print "header: %r" % "".join(headers)
	print "version: %r" % ord(headers[0])
	print "type: %r " % getType(ord(headers[1]))
	protocol = ord(headers[2])*256 + ord(headers[3])
	print "protocol %r" % getProtocol(protocol) 
	processTag(tags)
	print "data length: %r" % len(tags)
	packet = tags[1:]
	hexStr = "".join(tags[21:])
	iph = unpack('!BBHHHBBH4s4s',packet[14:34])
	version_ihl = iph[0]
    	version = version_ihl >> 4
   	ihl = version_ihl & 0xF
     
    	iph_length = ihl * 4
     
    	ttl = iph[5]
    	protocol = iph[6]
    	s_addr = socket.inet_ntoa(iph[8]);
    	d_addr = socket.inet_ntoa(iph[9]);
     	print map(ord,packet)
    	print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)	
	#print 'hexStr' + hexStr
     
     
	#break
