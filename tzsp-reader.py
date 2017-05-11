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

while True:
	data, addr = sock.recvfrom(1024)
	#print "received message: %r " % data.read(32).hex
	#print  str.encode(data[0])
	headers = data[0:4]
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
