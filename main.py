#! /usr/bin/env python3

from os import geteuid
from datetime import date
from pyshark import FileCapture
from optparse import OptionParser
from scapy.all import get_if_list
from colorama import Fore, Back, Style
from time import strftime, localtime

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

def check_root():
    return geteuid() == 0

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--iface", "iface", f"Network Interface on which sniffing has to be done ({','.join(get_if_list())})"),
                              ('-v', "--verbose", "verbose", "Display Additional Information related to the STUN Packets on the screen"),
                              ('-w', "--write", "write", "Dump the captured STUN Packets to File"),
                              ('-r', "--read", "read", "Read Packets from a Packet Capture File"))
    if arguments.read:
        try:
            packets = FileCapture(arguments.read)
        except FileNotFoundError:
            display('-', f"File {Back.YELLOW}{arguments.read}{Back.RESET} not found!")
            exit(0)
        except Exception as error:
            display('-', f"Error occured while reading Packets from File {Back.MAGENTA}{arguments.read}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
            exit(0)
    elif not arguments.iface or arguments.iface not in get_if_list():
        display('-', f"Please specify a valid {Back.YELLOW}Network Interface{Back.RESET} for Sniffing")
        exit(0)
    elif check_root():
        pass
    else:
        display('-', f"Please run this Program as {Back.YELLOW}root{Back.RESET} to Capture Live Packets from interface {Back.MAGENTA}{arguments.iface}{Back.RESET}")