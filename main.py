#! /usr/bin/env python3

from sys import path
from os import geteuid
from datetime import date
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
from pyshark import FileCapture, LiveCapture
from optparse import OptionParser
from scapy.all import get_if_list
from colorama import Fore, Back, Style
from time import strftime, localtime

path.append("IP-Location/IP Geolocation")

from ipgeolocation import *

path.append("../../")

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

stun_ips = set()
locate = True
locations = []
with open("ignore_asn_names.txt", 'r') as file:
    ignore_asns = [asn_name for asn_name in file.read().split('\n') if asn_name != '']

def check_root():
    return geteuid() == 0

def get_asn_name(ip):
    return IPWhois(ip).lookup_whois().get("asn_description")
def process_packet(packet):
    if "stun" in packet:
        if packet["ip"].src not in stun_ips:
            try:
                asn_name = get_asn_name(packet["ip"].src)
                return packet["ip"].src, packet["ip"].dst, asn_name, (True if len([asn for asn in ignore_asns if asn in asn_name]) == 0 else False)
            except IPDefinedError as error:
                pass
        if packet["ip"].dst not in stun_ips:
            try:
                asn_name = get_asn_name(packet["ip"].dst)
                return packet["ip"].dst, packet["ip"].src, asn_name, (True if len([asn for asn in ignore_asns if asn in asn_name]) == 0 else False)
            except IPDefinedError as error:
                pass
def capture_packet_callback(packet):
    info = process_packet(packet)
    if info == None:
        return
    elif info[3]:
        stun_ips.add(info[0])
        display('*', f"Detected STUN Packets from {Back.WHITE}{info[1]}{Back.RESET} => {Back.BLUE}{info[0]} ({info[2]}){Back.RESET}")
        if locate:
            locations.extend(get_ip_location([info[0]], verbose=True))
    elif arguments.verbose:
        stun_ips.add(info[0])
        display('*', f"{Back.MAGENTA}[VERBOSE: ASN in Ignore List]{Back.RESET} Detected STUN Packets from {Back.WHITE}{info[1]}{Back.RESET} => {Back.BLUE}{info[0]} ({info[2]}){Back.RESET}")
    else:
        stun_ips.add(info[0])

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--iface", "iface", f"Network Interface on which sniffing has to be done ({','.join(get_if_list())})"),
                              ('-v', "--verbose", "verbose", "Display Additional Information related to the STUN Packets on the screen"),
                              ('-l', "--locate", "locate", f"Locate Filtered IP Addresses (True/False, Default=True)"),
                              ('-w', "--write", "write", "Dump the captured STUN Packets to File"),
                              ('-r', "--read", "read", "Read Packets from a Packet Capture File"))
    arguments.verbose = True if arguments.verbose and arguments.verbose.lower() == "true" else False
    locate = False if arguments.locate and arguments.locate.lower() == "false" else True
    if arguments.read:
        try:
            packets = FileCapture(arguments.read)
        except FileNotFoundError:
            display('-', f"File {Back.YELLOW}{arguments.read}{Back.RESET} not found!")
            exit(0)
        except Exception as error:
            display('-', f"Error occured while reading Packets from File {Back.MAGENTA}{arguments.read}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
            exit(0)
        for packet in packets:
            info = process_packet(packet)
            if info == None:
                continue
            elif info[3]:
                stun_ips.add(info[0])
                display('*', f"Detected STUN Packets from {Back.WHITE}{info[1]}{Back.RESET} => {Back.BLUE}{info[0]} ({info[2]}){Back.RESET}")
                if locate:
                    locations.extend(get_ip_location([info[0]], verbose=True))
            elif arguments.verbose:
                stun_ips.add(info[0])
                display('*', f"{Back.MAGENTA}[VERBOSE: ASN in Ignore List]{Back.RESET} Detected STUN Packets from {Back.WHITE}{info[1]}{Back.RESET} => {Back.BLUE}{info[0]} ({info[2]}){Back.RESET}")
            else:
                stun_ips.add(info[0])
        if locate:
            locate_ip_on_map(locations)
    elif not arguments.iface or arguments.iface not in get_if_list():
        display('-', f"Please specify a valid {Back.YELLOW}Network Interface{Back.RESET} for Sniffing")
        exit(0)
    elif check_root():
        try:
            display(':', f"Starting Sniffing on {Back.MAGENTA}{arguments.iface}{Back.RESET} Interface...")
            capture = LiveCapture(interface=arguments.iface)
            capture.apply_on_packets(capture_packet_callback)
            capture.sniff()
        except KeyboardInterrupt:
            display(':', f"Stopped Sniffing on {Back.MAGENTA}{arguments.iface}{Back.RESET} Interface")
    else:
        display('-', f"Please run this Program as {Back.YELLOW}root{Back.RESET} to Capture Live Packets from interface {Back.MAGENTA}{arguments.iface}{Back.RESET}")