#!/usr/bin/env python2

import sys
import socket
import subprocess
import argparse
import struct
import time

parser = argparse.ArgumentParser()
parser.add_argument('--verbose','-v',action='store_true')
parser.add_argument('target',metavar='TARGET')
parser.add_argument('args',metavar='PORT[:PROTOCOL]',nargs='+')
arguments = parser.parse_args()

target = arguments.target
verbose = arguments.verbose
sequence = []

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


for i in range (0,len(arguments.args)):
    arguments.args_splitted = arguments.args[i].split(':')
    if len(arguments.args_splitted) > 2:
      print("Extra colon found (%s)"%(arguments.args[i]))
      sys.exit(1)
    elif len(arguments.args_splitted) == 2:
      sequence.append({ 'port': arguments.args_splitted[0], 'protocol': arguments.args_splitted[1]})
    else:
      if '/' in arguments.args[i]:
        sequence.append({ 'port': arguments.args_splitted[0], 'protocol': 'icmp'})
      else:
        sequence.append({ 'port': arguments.args_splitted[0], 'protocol': 'tcp'})


for s in sequence:
  if verbose:
    print("knocking on %s:%s (%s)"%(target,s['port'],s['protocol']))
  try:
    if s['protocol'] == 'tcp':
      tcp.connect((target,int(s['port'])))
    elif s['protocol'] == 'udp':
      udp.sendto('\n',(target,int(s['port'])))
  except socket.error:
    pass
  if s['protocol'] == 'icmp':
    icmp = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname('icmp'))
    icmp_type, icmp_code = s['port'].split('/')
    icmp_checksum =  (~((int(icmp_type) * 256 ) + int(icmp_code)) ) & 0xffff
    icmp.connect((target,22))
    icmp.send(struct.pack('!BBHI',int(icmp_type),int(icmp_code),icmp_checksum,0))
    icmp.close()
    #introduce a small delay not to overlay ICMP packets
    time.sleep(0.05)
