#!/usr/bin/env python2

import sys
from argparse import ArgumentParser

parser = ArgumentParser(description='It creates a safe port-knocking rules sequence to be used with iptables.\nICMP is supported (specify it with \"type/code:icmp\" (i.e. \"8/5:icmp\")')
parser.add_argument("args",metavar="SEQUENCE_PORT[:SEQUENCE_PROTOCOL]",nargs='+')
parser.add_argument("args",metavar="TARGET_PORT[:TARGET_PROTOCOL]", action='append')
arguments = parser.parse_args()


sequence = []
for i in range (0,len(arguments.args)):
    args_splitted = arguments.args[i].split(':')
    if len(args_splitted) > 3:
      print("Extra colon found (%s)"%(arguments.args[i]))
      sys.exit(1)
    elif len(args_splitted) == 3:
      sequence.append({ 'port': args_splitted[0], 'protocol': args_splitted[1], 'time': args_splitted[2]})
    elif len(args_splitted) == 2:
      sequence.append({ 'port': args_splitted[0], 'protocol': args_splitted[1], 'time': '5'})
    else:
      sequence.append({ 'port': args_splitted[0], 'protocol': 'tcp', 'time': '5'})

#parameters sanity check
for s in sequence:
  if s['protocol'] not in ('tcp','udp','icmp'):
    print('Invalid protocol specified (%s). Must be one of "tcp","udp" or "icmp"'%(s['protocol']))
    sys.exit(1)
  if s['protocol'] in ('tcp','udp') and not (s['port'].isdigit() and int(s['port']) in range(0,65536)):
    print('Invalid port specified (%s)'%(s['port']))
    sys.exit(1)
  if s['protocol'] == 'icmp':
    icmp_split = s['port'].split('/')
    if len(icmp_split) != 2 or not all(p.isdigit() and int(p) in range(0,256) for p in icmp_split):
      print('Invalid icmp specification (%s). Must be in form of "type/code"'%(s['port']))
      sys.exit(1)
  if not s['time'].isdigit():
    print("Invalid time specified (%s)"%(s['time']))
    sys.exit(1)
  
target = sequence[-1]
first_knock = sequence[0]

print("""*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]""")


#target port goes at the beginning so that it won't interfere with previous similar sequences
print("-A INPUT -p %s -m %s --dport %s -m state --state NEW"
      " -m recent --rcheck --name knock_%d --seconds %s --rsource -j ACCEPT"%
      (target['protocol'],target['protocol'],target['port'],len(sequence)-2,target['time']))


for i in range(len(sequence)-2,0,-1):
  if sequence[i]['protocol'] == 'icmp':
    print("-A INPUT -p icmp -m icmp --icmp-type %s"
          " -m recent --update --name knock_%d --seconds %s --rsource"
          " -m recent --remove --name knock_%d --rsource"
          " -m recent --set --name knock_%d  --rsource -j ACCEPT"%
          (sequence[i]['port'],i-1,sequence[i]['time'],i-1,i))
  elif sequence[i]['protocol'] in ('tcp','udp'):
    if sequence[i] == target:
      action = "REJECT --reject-with icmp-port-unreachable"
    else:
      action = "ACCEPT"
    print("-A INPUT -p %s -m %s --dport %s -m state --state NEW"
          " -m recent --update --name knock_%d --seconds %s --rsource"
          " -m recent --remove --name knock_%d --rsource"
          " -m recent --set --name knock_%d  --rsource -j %s"%
          (sequence[i]['protocol'],sequence[i]['protocol'],sequence[i]['port'],i-1,sequence[i]['time'],i-1,i,action))


if first_knock['protocol'] == 'icmp':
  print("-A INPUT -p icmp -m icmp --icmp-type %s"
        " -m recent --set --name knock_%d --rsource -j ACCEPT"%
        (first_knock['port'],0))
elif first_knock['protocol'] in ('tcp','udp'):
  if first_knock == target:
    action = "REJECT --reject-with icmp-port-unreachable"
  else:
    action = "ACCEPT"
  #first knock goes at the end so that it won't reset similar sequences
  print("-A INPUT -p %s -m %s --dport %s -m state --state NEW"
        " -m recent --set --name knock_%d --rsource -j %s"%(
        first_knock['protocol'],first_knock['protocol'],first_knock['port'],0,action))


print("-A INPUT -p %s -m %s --dport %s -m state --state NEW"
      " -j REJECT --reject-with icmp-port-unreachable"%(
      target['protocol'],target['protocol'],target['port']))
print("COMMIT")

