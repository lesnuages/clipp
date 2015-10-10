#coding: utf-8

import re
import dpkt
import hashlib
import socket
from collections import OrderedDict

# Patch RAW IP PCAP
from dpkt.pcap import dltoff, DLT_RAW
dltoff.update({101: DLT_RAW})

class Packet:

    def __init__(self, *args, **kwargs):
        self.data    = kwargs.get('data', None)
        self.strings = kwargs.get('strings', None)
        self.raw_ip  = kwargs.get('raw', None)

    def serialize(self):
        return {'data': self.data.encode('hex'), 'strings' : self.strings}

class Session:

    def __init__(self, *args, **kwargs):
        self.proto      = kwargs.get('proto', None)
        self.ip_src     = kwargs.get('ip_src', None)
        self.ip_dst     = kwargs.get('ip_dst', None)
        self.sport      = kwargs.get('sport', None)
        self.dport      = kwargs.get('dport', None)
        self.packets    = []

    def add_packet(self, packet):
        self.packets.append(packet)

    @property
    def tot_len(self):
        return sum([len(pkt.data) for pkt in self.packets])

    @property
    def nb_pkts(self):
        return len(self.packets)

    def serialize(self):
        return {'proto': self.proto,
               'ip_src' : self.ip_src,
               'ip_dst' : self.ip_dst,
               'sport'  : self.sport,
               'dport'  : self.dport,
               'pkts'   : self.nb_pkts,
               'tot_len' : self.tot_len}

class PcapAnalyzer():

    def __init__(self):
        self.sessions   = OrderedDict()
        self.filepath   = None

    def set_filepath(self, filepath):
        """
        Simple setter
        """
        self.filepath = filepath

    def parse_file(self, mobile=False, prod=False):
        """
        Parse the input file.
        """
        with open(self.filepath) as pcap_stream:
            pcap = dpkt.pcap.Reader(pcap_stream)
            pcap.loop(self.handle_packet, mobile, prod)

    def handle_packet(self, ts, buff, mobile=False, prod=False):
        if prod:
            ip = dpkt.ip.IP(buff)
        else:
            eth = dpkt.ethernet.Ethernet(buff[2:]) if mobile else dpkt.ethernet.Ethernet(buff)
            ip = eth.data
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                return
        if ip.p in [dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP] and len(ip.data.data) > 0:
            self.sessionize(ip)
    
    def sessionize(self, ip):
        hkey = self.compute_key(ip)
        if hkey:
            proto = {dpkt.ip.IP_PROTO_TCP: 'TCP', dpkt.ip.IP_PROTO_UDP:'UDP'}[ip.p]
            strings = self.find_strings(ip.data.data)
            packet = Packet(data=ip.data.data, strings=strings, raw=ip)
            if hkey in self.sessions.keys():
                self.sessions[hkey].add_packet(packet)
            else:
                session = Session(proto=proto,
                                  ip_src=self.ip_to_str(ip.src),
                                  ip_dst=self.ip_to_str(ip.dst),
                                  sport=ip.data.sport,
                                  dport=ip.data.dport)
                session.add_packet(packet)
                self.sessions.update({hkey:session})

    def find_strings(self, data):
        return "".join(re.findall(u'(?i)[\b-\r -ÿ]', data))

    def ip_to_str(self, address):
        return socket.inet_ntop(socket.AF_INET, address)

    def compute_key(self, ip_data):
        if ip_data.p in [dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP]:
            src = ip_data.src.encode('hex')
            dst = ip_data.dst.encode('hex')
            sport = ip_data.data.sport
            dport = ip_data.data.dport
            return hashlib.sha1('%s%s%s%s%s' % (min(src,dst), max(src,dst), min(sport,dport), max(sport,dport), ip_data.p)).digest().encode('hex')
