#!/usr/bin/env python3
import socket
import struct
import impacket
import selectors
import os
import ipaddress
import collections
import time
import sys
from impacket.IP6 import IP6
from impacket import ImpactDecoder
from impacket.ImpactPacket import IP, TCP, UDP
from pytun import TunTapDevice
import argparse
import random

packet_queue = collections.deque()
loss_ratio = -1
delay = 0
random_drop = False
later_delay = 0
later_loss = 0
test_start = -1
switched = False

class _ConnectionKey(object):
    """ Represent a unique 5-tuple (src/dst IP/port + protocol) in manner that disregards the order
        of the source and destination. The primary purpose of this class is to allow TCP/UDP
        connections to be used as keys in native Python dictionaries.
    """

    def __init__(self, ip1, port1, ip2, port2, proto):
        """ Initialize the ConnectionKey without regard to the whether the IP address of
            IP1 or IP2 are on the local network.
            The connection_key puts the smaller IP address in IP1. It breaks ties with port number.
        """
        ip1_obj = ipaddress.ip_address(ip1)
        ip2_obj = ipaddress.ip_address(ip2)
        if(ip1_obj < ip2_obj or ((ip1_obj == ip2_obj) and (port1 <= port2))):
            self.ip1 = ip1
            self.port1 = port1
            self.ip2 = ip2
            self.port2 = port2
            self.proto = proto
        else: #(ip2 < ip1 or ((ip1 == ip2) and port2 < port1)))
            self.ip1 = ip2
            self.port1 = port2
            self.ip2 = ip1
            self.port2 = port1
            self.proto = proto

    #def increment_packet(self, srcIP, sport, dstIP, dport):
    #    if(self.ip1==srcIP and self.port1==sport and self.ip2==dstIP and self.port2==dport):
    #        self.one_to_two_pkts += 1
    #    elif(self.ip2==srcIP and self.port2==sport and self.ip1==dstIP and self.port1==dport):
    #        self.two_to_one_pkts += 1
    #    else:
    #        print("incrment called on wrong")

    def __hash__(self):
        return hash((str(self.ip1), self.port1, str(self.ip2), self.port2, self.proto))

    def __eq__(self, other):
        return (isinstance(self, type(other)) and
                str(self.ip1) == str(other.ip1) and
                self.port1 == other.port1 and
                str(self.ip2) == str(other.ip2) and
                self.port2 == other.port2 and
                self.proto == other.proto)


class _ConnTracker():
    def __init__(self):
        self.conn_dict = {}

    def increment_packet(self, srcIP, sport, dstIP, dport, prot):
        key = _ConnectionKey(srcIP, sport, dstIP, dport, prot)
        if key not in self.conn_dict:
            self.conn_dict[key] = {'1to2Packets':0, '2to1Packets':0}
        if(key.ip1==srcIP and key.port1==sport and key.ip2==dstIP and key.port2==dport):
            self.conn_dict[key]['1to2Packets']+=1
        elif(key.ip2==srcIP and key.port2==sport and key.ip1==dstIP and key.port1==dport):
            self.conn_dict[key]['2to1Packets']+=1
        else:
            print("Error")

    def get_pkt_count(self, srcIP, sport, dstIP, dport, prot):
        key = _ConnectionKey(srcIP, sport, dstIP, dport, prot)
        if key not in self.conn_dict:
            print("Key not found in conn_dict")
        if(key.ip1==srcIP and key.port1==sport and key.ip2==dstIP and key.port2==dport):
            return self.conn_dict[key]['1to2Packets']
        elif(key.ip2==srcIP and key.port2==sport and key.ip1==dstIP and key.port1==dport):
            return self.conn_dict[key]['2to1Packets']
        else:
            print("Error")

def get_packet_time(ancdata):
    #for element in ancdata:
    #    if(element[1]==SO_TIMESTAMPNS):
    #        ts=(struct.unpack("iiii",element[2]))
    #        timestamp = ts[0] + ts[2]*1e-10
    #        return(timestamp)
    #return(-1)
    return(time.clock_gettime_ns(time.CLOCK_REALTIME)/1e9)


def receivepacket(conn, mask, conn_partner,conn_tracker):
    raw_data = conn.read(65535)
    #Begin tracking received packet
    try:
        packet = decoder.decode(raw_data[4:])
    except:
        print("Unable to decode packet!")
        return
    #try:
    #    packet = frame.child()
    #except:
        # Most likely reason for exception is that impacket cannot find a packet within the
        # frame. As these frames are not interesting to us, we can safely re-enter the loop
        # without making any updates
    #    return
    #print(raw_data.hex())
    prot = 0
    src = None
    dst = None
    ip_len = 0
    isAnyIP = False
    losePacket = False
    if isinstance(packet,IP):
        prot = packet.get_ip_p()
        src = packet.get_ip_src()
        dst = packet.get_ip_dst()
        ip_len = packet.get_ip_len()
        isAnyIP = True
    if isinstance(packet,IP6):
        prot = packet.get_next_header()
        src = packet.get_ip_src()
        dst = packet.get_ip_dst()
        ip_len = packet.get_size()
        isAnyIP = True
    if(isAnyIP):
        segment = packet.child()
        sport = 0
        dport = 0
        if isinstance(segment,TCP):
            sport = segment.get_th_sport()
            dport = segment.get_th_dport()
        elif isinstance(segment,UDP):
            sport = segment.get_uh_sport()
            dport = segment.get_uh_dport()
        #print("Packet Received. Src IP: " + str(src) + " Dst IP: " + str(dst) + " Src Port: " + str(sport) + " Dst Port: " + str(dport))
        conn_tracker.increment_packet(src,sport,dst,dport,prot)
        pkts = conn_tracker.get_pkt_count(src,sport,dst,dport,prot)
        curr_loss_ratio = -1
        curr_delay = 0
        if time.clock_gettime(time.CLOCK_BOOTTIME) < test_start + 180:
            curr_loss_ratio = loss_ratio
            curr_delay = delay
        else:
            # Print precise time
            global switched
            if switched is False:
                print("switch," + str(time.clock_gettime_ns(time.CLOCK_REALTIME)/1e9))
                switched = True
                sys.stdout.flush()
            curr_loss_ratio = later_loss
            curr_delay = later_delay
        if curr_loss_ratio != -1:
            if random_drop:
                random_num = random.random()
                losePacket = random_num < (1 / curr_loss_ratio)
            else:
                losePacket = pkts % curr_loss_ratio == 0
        #print("Packets: " + str(pkts))
        #if "tun" in loss_dictionary:
        #    print("tun in loss dictionary") 
        #    if pkts % loss_dictionary["tun"] == 0:
        #        losePacket = True
    if(losePacket):
        print("drop," + str(time.clock_gettime_ns(time.CLOCK_REALTIME)/1e9) + "," + str(src) + "," + str(sport) + "," + str(dst) + "," + str(dport) + "," + str(prot))
        sys.stdout.flush()
    else:
        try:
            #conn_partner.sendall(raw_data)
            pkt_time = time.clock_gettime_ns(time.CLOCK_REALTIME)/1e9
            #print("Packet time: " + str(pkt_time))
            if pkt_time == -1:
                print("Bad time received!")
            else:
                packet_queue.append((pkt_time+curr_delay,conn_partner,raw_data))
            #print(packet_queue.popleft())
        except OSError:
            print(len(raw_data))

        
        
tun = TunTapDevice(name='lossem')
tun.addr = '192.168.250.1'
tun.netmask = '255.255.255.0'
tun.up()
sel = selectors.DefaultSelector()
sel.register(tun, selectors.EVENT_READ, (receivepacket,tun))
decoder = ImpactDecoder.IPDecoder()

parser = argparse.ArgumentParser()
parser.add_argument("delay", help="Delay every packet by this number of milliseconds", type=int)
parser.add_argument("loss", help="Drop every this number of packets. -1 to disable.", type=int)
parser.add_argument("random_drop", help="Drop packets randomly instead of deterministically", choices=['true', 'false'])
parser.add_argument("later_delay", help="Delay every packet by this number of milliseconds after 3 minutes", type=int)
parser.add_argument("later_loss", help="Drop every this number of packets after 3 minutes. -1 to disable.", type=int)
args = parser.parse_args()
loss_ratio = args.loss
delay = args.delay / 1000
random_drop=False
if(args.random_drop=='true'):
    random_drop=True
later_delay = args.later_delay / 1000
later_loss = args.later_loss
test_start = time.clock_gettime(time.CLOCK_BOOTTIME)

conn_tracker = _ConnTracker()
to = None
while True:
    #print("Enter select loop: " + str(time.clock_gettime_ns(time.CLOCK_REALTIME)/1e9))
    events = sel.select(to)
    #print("Exit select loop: " + str(time.clock_gettime_ns(time.CLOCK_REALTIME)/1e9))
    for key, mask in events:
        (callback,parameter) = key.data
        callback(key.fileobj, mask, parameter,conn_tracker)
    search=True
    while len(packet_queue)>0 and search:
        if(packet_queue[0][0]<=time.clock_gettime_ns(time.CLOCK_REALTIME)/1e9):
            (ts,conn_handle,data)=packet_queue.popleft()
            #print("Sending now: " + str(time.clock_gettime_ns(time.CLOCK_REALTIME)/1e9) + " ts: " + str(ts))
            conn_handle.write(data)
        else:
            search=False
            #print("Done searching")
    if(len(packet_queue)>0):
        to = packet_queue[0][0] - time.clock_gettime_ns(time.CLOCK_REALTIME)/1e9
        #print("Packets waiting to be sent in: " + str(to))
    else:
        to = None
        #print("Nothing to be sent")