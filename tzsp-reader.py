import socket
import struct

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
	print 'length: ',len(data)
	resp = "-"

	#print "type:", struct.unpack("!B", data[1])
	#for dataItem in data:
        #	resp = resp+"-"+ str(struct.unpack("!B", dataItem)[0]) # (note 2)	
		
	#print resp
