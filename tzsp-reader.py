import socket
import struct
import binascii
from struct import *

UDP_IP = "0.0.0.0"
UDP_PORT = 37008 

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind((UDP_IP,UDP_PORT))

def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

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

def getEtherType(etherInt):
	types = {
		0x0800 : 'Internet Protocol version 4 (IPv4)',
		0x0806 : 'Address Resolution Protocol (ARP)',
		0x0842 : 'Wake-on-LAN',
		0x22F3 : 'IETF TRILL Protocol',
		0x6003: 'DECnet Phase IV',
		0x8035: 'Reverse Address Resolution Protocol',
		0x809B: 'AppleTalk (Ethertalk)',
		0x80F3: 'AppleTalk Address Resolution Protocol (AARP)',
		0x8100: 'VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq[8]',
		0x8137: 'IPX',
		0x8204: 'QNX Qnet',
		0x86DD: 'Internet Protocol Version 6 (IPv6)',
		0x8808: 'Ethernet flow control',
		0x8819: 'CobraNet',
		0x8847: 'MPLS unicast',
		0x8848: 'MPLS multicast',
		0x8863: 'PPPoE Discovery Stage',
		0x8864: 'PPPoE Session Stage',
		0x8870: 'Jumbo Frames (Obsoleted draft-ietf-isis-ext-eth-01)',
		0x887B: 'HomePlug 1.0 MME',
		0x888E: 'EAP over LAN (IEEE 802.1X)',
		0x8892: 'PROFINET Protocol',
		0x889A: 'HyperSCSI (SCSI over Ethernet)',
		0x88A2: 'ATA over Ethernet',
		0x88A4: 'EtherCAT Protocol',
		0x88A8: 'Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[8]',
		0x88AB: 'Ethernet Powerlink[citation needed]',
		0x88B8: 'GOOSE (Generic Object Oriented Substation event)',
		0x88B9: 'GSE (Generic Substation Events) Management Services',
		0x88BA: 'SV (Sampled Value Transmission)',
		0x88CC: 'Link Layer Discovery Protocol (LLDP)',
		0x88CD: 'SERCOS III',
		0x88E1: 'HomePlug AV MME[citation needed]',
		0x88E3: 'Media Redundancy Protocol (IEC62439-2)',
		0x88E5: 'MAC security (IEEE 802.1AE)',
		0x88E7: 'Provider Backbone Bridges (PBB) (IEEE 802.1ah)',
		0x88F7: 'Precision Time Protocol (PTP) over Ethernet (IEEE 1588)',
		0x88FB: 'Parallel Redundancy Protocol (PRP)',
		0x8902: 'IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)',
		0x8906: 'Fibre Channel over Ethernet (FCoE)',
		0x8914: 'FCoE Initialization Protocol',
		0x8915: 'RDMA over Converged Ethernet (RoCE)',
		0x891D: 'TTEthernet Protocol Control Frame (TTE)',
		0x892F: 'High-availability Seamless Redundancy (HSR)',
		0x9000: 'Ethernet Configuration Testing Protocol[9]',
		0x9100: 'VLAN-tagged (IEEE 802.1Q) frame with double tagging'
	}
	return types[etherInt]

def processTag(tag):
	currentTag = None
	i = 0
	while currentTag not in [0x00, 0x01]:
 		currentTag = ord(tag[i])
		tagType = getTagType(ord(tag[0]))
		tagLength = 0
		if(tagType not in ["TAG_END","TAG_PADDING"]):
			tagLength = ord(tag[1])
		
		i = i + 1 + tagLength
		print "tag type: %r" % tagType
		print "tag length: %r" % tagLength
	return i
	
while True:
	data, addr = sock.recvfrom(1024)

	headers = data[0:4]
	tags = data[4:]

	#print "header: %r" % "".join(headers)
	print "version: %r" % ord(headers[0])
	print "type: %r " % getType(ord(headers[1]))
	protocol = ord(headers[2])*256 + ord(headers[3])
	print "protocol %r" % getProtocol(protocol) 
	tagsLength = processTag(tags)
	print "data length: %r" % tagsLength
	eth_header = tags[tagsLength:15]
	eth = unpack('!6s6sH' , eth_header)
    	eth_protocol = socket.ntohs(eth[2])
    	print 'Destination MAC : ' + eth_addr(eth_header[0:6]) + ' Source MAC : ' + eth_addr(eth_header[6:12]) + ' Protocol : ' + str(eth_protocol) + ' EtherType: ' + getEtherType(eth[2])
	
	packet = tags[15:]
	hexStr = "".join(tags[21:])
	iph = unpack('!BBHHHBBH4s4s',packet[:20])
	version_ihl = iph[0]
    	version = version_ihl >> 4
   	ihl = version_ihl & 0xF
     
    	iph_length = ihl * 4
     
    	ttl = iph[5]
    	protocol = iph[6]
    	s_addr = socket.inet_ntoa(iph[8]);
    	d_addr = socket.inet_ntoa(iph[9]);
     	#print map(ord,packet)
    	print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)	
	#print 'hexStr' + hexStr
     
     
	#break
