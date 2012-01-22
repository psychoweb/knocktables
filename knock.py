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
parser.add_argument('sequence',metavar='TOKEN[:MODE]',nargs='+')
arguments = parser.parse_args()

target = arguments.target
verbose = arguments.verbose
sequence = []

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


for i in range (0,len(arguments.sequence)):
    sequence_splitted = arguments.sequence[i].split(':')
    if len(sequence_splitted) > 2:
      print("Extra colon found (%s)"%(arguments.sequence[i]))
      sys.exit(1)
    elif len(sequence_splitted) == 2:
      sequence.append({ 'token': sequence_splitted[0], 'mode': sequence_splitted[1]})
#auto-guess mode
    else:
      if '/' in arguments.sequence[i]:
        sequence.append({ 'token': sequence_splitted[0], 'mode': 'icmp'})
      elif arguments.sequence[i].startswith('0x'):
        sequence.append({ 'token': sequence_splitted[0], 'mode': 'idseq'})
      else:
        sequence.append({ 'token': sequence_splitted[0], 'mode': 'tcp'})


for s in sequence:
  if verbose:
    print("knocking on %s:%s (%s)"%(target,s['token'],s['mode']))
  try:
    if s['mode'] == 'tcp':
      tcp.connect((target,int(s['token'])))
    elif s['mode'] == 'udp':
      udp.sendto('\n',(target,int(s['token'])))
  except socket.error:
    pass
  if s['mode'] == 'icmp':
    icmp = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname('icmp'))
    icmp_type, icmp_code = s['token'].split('/')
    icmp_checksum =  (~((int(icmp_type) * 256 ) + int(icmp_code)) ) & 0xffff
    icmp.connect((target,42))
    icmp.send(struct.pack('!BBHI',int(icmp_type),int(icmp_code),icmp_checksum,0))
    icmp.close()
    #introduce a small delay not to overlay ICMP packets
    time.sleep(0.05)
  elif s['mode'] == 'idseq':
    icmp = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname('icmp'))
    icmp_idseq = s['token']
    icmp_checksum =  (~((8 * 256 ) + 0 + (int(icmp_idseq,16)) ) ) & 0xffff
    icmp.connect((target,42))
    icmp.send(struct.pack('!BBHI',8,0,icmp_checksum,int(icmp_idseq,16)))
    icmp.close()
    #introduce a small delay not to overlay ICMP packets
    time.sleep(0.05)
   
