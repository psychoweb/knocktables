#!/usr/bin/env python2

import sys
from argparse import ArgumentParser,RawDescriptionHelpFormatter


parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,description='Creates a safe port-knocking rules sequence to be used with iptables.',
epilog="""MODE:
    tcp: attempts to establish a TCP connection to TOKEN port
    udp: sends an UDP datagram to TOKEN port
   icmp: sends a custom ICMP packet with type and code specified by TOKEN separated by '/' (ex: '8/5')
  idseq: sends an ICMP Echo Request (ping) packet with a 4-bytes hex value reserved for "Identifier" and "Sequence Number"
payload: sends an ICMP Echo Request (ping) packet with a 4-bytes hex attached payload specified by TOKEN [RECOMMENDED]
""")
parser.add_argument("--iptables", action="store_true",default=False)
parser.add_argument("sequence",metavar="TOKEN[:MODE]",nargs='+')
parser.add_argument("sequence",metavar="TARGET_PORT[:TARGET_PROTOCOL]", action='append')
arguments = parser.parse_args()

#removing 'icmp' mode as idseq is more reliable
allowed_modes = ('tcp','udp','idseq','payload')
sequence = []

#set default values
for i in range (0,len(arguments.sequence)):
    sequence_splitted = arguments.sequence[i].split(':')
    if len(sequence_splitted) > 3:
      print("Extra colon found (%s)"%(arguments.sequence[i]))
      sys.exit(1)
    elif len(sequence_splitted) == 3:
      sequence.append({ 'token': sequence_splitted[0], 'mode': sequence_splitted[1], 'time': sequence_splitted[2]})
    elif len(sequence_splitted) == 2:
      sequence.append({ 'token': sequence_splitted[0], 'mode': sequence_splitted[1], 'time': '5'})
    else:
#auto-guess modes
      if '/' in arguments.sequence[i]:
        sequence.append({ 'token': sequence_splitted[0], 'mode': 'icmp', 'time': '5'})
      elif arguments.sequence[i].lower().startswith('0x'):
        sequence.append({ 'token': sequence_splitted[0], 'mode': 'payload', 'time': '5'})
      else:
        sequence.append({ 'token': sequence_splitted[0], 'mode': 'tcp', 'time': '5'})

#parameters sanity check
for s in sequence:
  if s['mode'] not in allowed_modes:
    print('Invalid mode specified (%s). Must be one of %s'%(s['mode'],allowed_modes))
    sys.exit(1)
  if s['mode'] in ('tcp','udp') and not (s['token'].isdigit() and int(s['token']) in range(0,65536)):
    print('Invalid token specified (%s)'%(s['token']))
    sys.exit(1)
  if s['mode'] == 'icmp':
    icmp_split = s['token'].split('/')
    if len(icmp_split) != 2 or not all(p.isdigit() and int(p) in range(0,256) for p in icmp_split):
      print('Invalid icmp specification (%s). Must be in form of "type/code"\n(with "type" and "code" between 0 and 255)'%(s['token']))
      sys.exit(1)
  if s['mode'] in ('idseq','payload'):
    try:
      icmp_bytes = int(s['token'],16)
      if icmp_bytes > 0xFFFFFFFF :
        raise ValueError()
    except ValueError:
      print('Invalid idseq specified (%s). Must be a valid 4-bytes hex value (ex: 0xF9E80C)'%(s['token']))
      sys.exit(1)
  if not s['time'].isdigit():
    print("Invalid time specified (%s)"%(s['time']))
    sys.exit(1)
if sequence[-1]['mode'] not in ('tcp','udp'):
  print('Target (last sequence) mode must be one of "tcp","udp" (it can\'t be "icmp")')
  sys.exit(1)  

target = sequence[-1]
first_knock = sequence[0]

if arguments.iptables:
    #rules preamble
    print("*filter\n"
          ":INPUT ACCEPT [0:0]\n"
          ":FORWARD ACCEPT [0:0]\n"
          ":OUTPUT ACCEPT [0:0]""")
    
    
    #target token goes at the beginning so that it won't interfere with previous similar sequences
    print("-A INPUT -p %s -m %s --dport %s -m state --state NEW"
          " -m recent --rcheck --name knock_%d --seconds %s --rsource"
          " -m recent --remove --name knock_%d --rsource -j ACCEPT"%
          (target['mode'],target['mode'],target['token'],len(sequence)-2,target['time'],len(sequence)-2))
    
    #insert rules in reverse order
    for i in range(len(sequence)-2,0,-1):
      if sequence[i]['mode'] == 'icmp':
        print("-A INPUT -p icmp -m icmp --icmp-type %s"
              " -m recent --update --name knock_%d --seconds %s --rsource"
              " -m recent --remove --name knock_%d --rsource"
              " -m recent --set --name knock_%d  --rsource -j ACCEPT"%
              (sequence[i]['token'],i-1,sequence[i]['time'],i-1,i))
      elif sequence[i]['mode'] == 'idseq':
        print("-A INPUT -p icmp -m icmp --icmp-type 8/0"
              " -m u32 --u32 0>>22&0x3C@4&0xFFFFFFFF=%s"
              " -m recent --update --name knock_%d --seconds %s --rsource"
              " -m recent --remove --name knock_%d --rsource"
              " -m recent --set --name knock_%d  --rsource -j ACCEPT"%
              (sequence[i]['token'],i-1,sequence[i]['time'],i-1,i))
      elif sequence[i]['mode'] == 'payload':
        print("-A INPUT -p icmp -m icmp --icmp-type 8/0"
              " -m u32 --u32 0>>22&0x3C@8&0xFFFFFFFF=%s"
              " -m recent --update --name knock_%d --seconds %s --rsource"
              " -m recent --remove --name knock_%d --rsource"
              " -m recent --set --name knock_%d  --rsource -j ACCEPT"%
              (sequence[i]['token'],i-1,sequence[i]['time'],i-1,i))
    
      elif sequence[i]['mode'] in ('tcp','udp'):
        if sequence[i] == target:
          action = "REJECT --reject-with icmp-port-unreachable"
        else:
          action = "ACCEPT"
        print("-A INPUT -p %s -m %s --dport %s -m state --state NEW"
              " -m recent --update --name knock_%d --seconds %s --rsource"
              " -m recent --remove --name knock_%d --rsource"
              " -m recent --set --name knock_%d  --rsource -j %s"%
              (sequence[i]['mode'],sequence[i]['mode'],sequence[i]['token'],i-1,sequence[i]['time'],i-1,i,action))
    
    
    #first knock goes at the end so that it won't reset similar sequences
    if first_knock['mode'] == 'icmp':
      print("-A INPUT -p icmp -m icmp --icmp-type %s"
            " -m recent --set --name knock_%d --rsource -j ACCEPT"%
            (first_knock['token'],0))
    elif first_knock['mode'] == 'idseq':
      print("-A INPUT -p icmp -m icmp --icmp-type 8/0"
            " -m u32 --u32 0>>22&0x3C@4&0xFFFFFFFF=%s"
            " -m recent --set --name knock_%d --rsource -j ACCEPT"%
            (first_knock['token'],0))
    elif first_knock['mode'] == 'payload':
      print("-A INPUT -p icmp -m icmp --icmp-type 8/0"
            " -m u32 --u32 0>>22&0x3C@8&0xFFFFFFFF=%s"
            " -m recent --set --name knock_%d --rsource -j ACCEPT"%
            (first_knock['token'],0))
    elif first_knock['mode'] in ('tcp','udp'):
      if first_knock == target:
        action = "REJECT --reject-with icmp-port-unreachable"
      else:
        action = "ACCEPT"
      print("-A INPUT -p %s -m %s --dport %s -m state --state NEW"
            " -m recent --set --name knock_%d --rsource -j %s"%(
            first_knock['mode'],first_knock['mode'],first_knock['token'],0,action))
    
    #deny target otherwise
    print("-A INPUT -p %s -m %s --dport %s -m state --state NEW"
          " -j REJECT --reject-with icmp-port-unreachable"%(
          target['mode'],target['mode'],target['token']))
    print("COMMIT")


else:
    print("""#!/usr/bin/env nft -f
          flush ruleset
    
          table ip Inet4 {""")
    for i in range(len(sequence)-1):
        print("""\tset Knocked_{} {{
              \ttype ipv4_addr
              \tflags timeout
              \ttimeout {}s
              \tgc-interval 5s
              }}""".format(str(i),sequence[i]['time']))
    
    print("""\tchain Knock_0 {
             \tset add ip saddr @Knocked_0
             \t}""")
    
    for i in range(1,len(sequence)-1):
        #setting timeout to 0s does not work: https://www.spinics.net/lists/netfilter/msg58017.html
        print("""
        chain Knock_{} {{
          set update ip saddr timeout 1s @Knocked_{}
          set add ip saddr @Knocked_{}
        }}
        """.format(i,i-1,i))
    
    print("""chain PortKnock_{}_{} {{
        {} dport {} ct state new ip saddr @Knocked_{} accept""".format(target['token'],target['mode'],target['mode'],target['token'],len(sequence) -2))
    for i in range(len(sequence)-2,0,-1):
         print("""    {} dport {} ct state new ip saddr @Knocked_{} goto Knock_{}""".format(sequence[i]['mode'],sequence[i]['token'],i-1,i))
    print("    {} dport {} ct state new goto Knock_0\n }}".format(first_knock['mode'],first_knock['token']))
    print("""
        chain FilterIn {{
        type filter hook input priority 0
        policy accept
    
        # allow established/related connections
        ct state established,related accept
    
        # port-knocking
        jump PortKnock_{}_{}
        {} dport {} ct state new drop
    
      }}
    
    }}""".format(target['token'],target['mode'],target['mode'],target['token']))
    
