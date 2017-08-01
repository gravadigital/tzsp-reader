# -*- coding: utf-8 -*-
import socket
import os
import sys
import struct
import binascii
import json
import time
import math
import curses
import locale
from struct import *
from operator import itemgetter

starttime=time.time()
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

def processTag(tag,details=False):
	currentTag = None
	i = 0
	while currentTag not in [0x00, 0x01]:
 		currentTag = ord(tag[i])
		tagType = getTagType(ord(tag[0]))
		tagLength = 0
		if(tagType not in ["TAG_END","TAG_PADDING"]):
			tagLength = ord(tag[1])

		i = i + 1 + tagLength
		if details:
			print "tag type: %r" % tagType
			print "tag length: %r" % tagLength
	return i

def processUdpData(data,addr):
	headers = data[0:4]
        tags = data[4:]

        #print "header: %r" % "".join(headers)
        #print "version: %r" % ord(headers[0])
        #print "type: %r " % getType(ord(headers[1]))
        protocol = ord(headers[2])*256 + ord(headers[3])
        protocolStr = getProtocol(protocol)

        tagsLength = processTag(tags)
        #print "tags length: %r" % tagsLength
        eth_header = tags[tagsLength:(14+tagsLength)]
        eth_data = tags[(14+tagsLength):]

        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        mac_details = 'Destination MAC : ' + eth_addr(eth_header[0:6]) + ' Source MAC : ' + eth_addr(eth_header[6:12]) + ' Protocol : ' + str(eth_protocol)

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
        connection_detail = ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
	return {"s_addr":s_addr,"d_addr":d_addr,"len":len(eth_data),"connection_detail":connection_detail,"mac_details":mac_details}
def readIpFile(fileName='./ipfile.json'):
    if(os.path.isfile(fileName)):
        with open(fileName,'r') as configFile:
            ipNames = json.load(configFile)
        return ipNames
    else:
        return False

def Average(previusAverage = 0, value = 0, quantity = 1):
	return float(previusAverage) * ( (int(quantity)-1) / int(quantity) ) + float(value) / int(quantity)

try:
    consumes = {}
    average_consumes = {}
    average_count = {}
    encoding="utf-8"
    history_lines = []
    available = True
    stdscr = curses.initscr()
    ipNames = readIpFile()
    curses.nocbreak(); stdscr.keypad(1); curses.echo();
    curses.curs_set(0)
    stdscr.border(0)

    rows, columns = stdscr.getmaxyx()
    columns -= 2
    consums_panel = curses.newpad((rows -2)/2, (columns -2)/2)
    consums_panel.border(0)
    average_panel = curses.newpad((rows -2)/2, (columns -2)/2)
    average_panel.border(0)

    log_panel = curses.newpad((rows - 2)/2, columns - 2)
    log_panel.border(0)
    log_panel_rows, log_panel_columns = log_panel.getmaxyx()
    log_panel_rows -= 2
    stdscr.refresh()
    consums_panel.refresh(0,0,1,2,rows,columns)
    average_panel.refresh(0,0,1,(columns/2) + 2 ,rows,columns)
    log_panel.refresh(0,0,(rows/2),2,rows+2,columns)

    line = 0
    consum_msg=[]
    average_msg=[]
    while True:
        data, addr = sock.recvfrom(1024)
        consumesData = processUdpData(data,addr)
        if len(history_lines) > 100000:
            history_lines = history_lines[-1000:]
        history_lines.append(consumesData['connection_detail'].ljust(columns-5))
        timer = math.floor((time.time() % 2.0))
        if "192.168." in str(consumesData['d_addr']):
            d_addr = str(consumesData['d_addr'])
            size = consumesData['len']
            if d_addr not in consumes:
                consumes[d_addr] = 0
            consumes[d_addr] += size
        if timer == 1:
           available = True
        if timer == 0 and available == True:
            consum_msg = []
            average_msg = []
            for ip,size in sorted(consumes.items(), key=itemgetter(1), reverse=True):
                kbps_size = round((size/4)/1024)*10
                ipLabel = ip
                if(ip in ipNames):
                        ipLabel = ipNames[ip]
                if size != 0:
                    consum_msg.append(str("IP: " + ipLabel + " - " +  str(round((size/4)/1024)*10).strip() + " kb/s - " + str(size/2)).ljust((columns/2)-15))
                    if not ip in average_count:
                        average_count[ip] = 0
                        average_count[ip] += 1
                        if not ip in average_consumes:
                            average_consumes[ip] = 0
                            average_consumes[ip] = Average(average_consumes[ip], kbps_size, average_count[ip])
                consumes[ip] = 0
            for ip, average in sorted(average_consumes.items(), key = itemgetter(1), reverse = True):
                ipLabel = ip
                if(ip in ipNames):
                    ipLabel = ipNames[ip]
                average_msg.append(str("average: " + ipLabel + " - " + str(average).strip() + " kb/s").ljust((columns/2)-15))
            available = False
            j = 1
            maxrows = (rows/2-3)
            for msg in consum_msg[:maxrows]:
                consums_panel.addstr(j,2,msg)
                j+=1
            m=1
            for msg in average_msg[:maxrows]:
                average_panel.addstr(m,2,msg)
                m+=1

        h = 1
        for log in history_lines[-(rows/2-3):]:
            log_panel.addstr(h,2,log.ljust(columns/2))
            h+=1
        consums_panel.refresh(0,0,1,2,rows,columns)
        average_panel.refresh(0,0,1,(columns/2) + 2 ,rows,columns)
        log_panel.refresh(0,0,(rows/2),2,rows+2,columns)

finally:
    curses.nocbreak();stdscr.keypad(0);curses.echo();
    curses.endwin()
