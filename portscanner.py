#!/usr/bin/env python3

# simple port scanner
# loading imports
from termcolor import colored
import threading
import optparse
import socket
import sys
# 
def portScan(tgIP, tgPort):
  # checking if host valid
  try:
   tgIP = socket.gethostbyname(tgIP)
  except:
    print(colored(f"[-] Host {tgIP} Unknown Cannot resolve Host !!!","red"))
    sys.exit()
  host = (tgIP, tgPort)
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(host)
    print(f'[+] Host {tgIP}  Port {tgPort}/Open')
  except:
    print(f'[-] Host {tgIP}  Port {tgPort}/closed')
    
# displays this script usage to users and initate the program if usage is valid
def main():
  parser = optparse.OptionParser(f'\n{colored("[Dev] Peter Nyando --> www.github.com/anomalou254 ", "blue")} \n[+] Usage: {sys.argv[0]} -H <TARGETHOST> -p <TARGETPORT>')
  parser.add_option('-H', dest='targetHost', type='string', help='Specify target IP')
  parser.add_option('-p', dest='targetPort', type='int', help='Specify Port')
  (options, args) = parser.parse_args()
  
  targetHost = options.targetHost
  targetPort = options.targetPort
  
  # checking if the user specified the worflow data else prints the script usage
  if options.targetHost == None or options.targetPort == None:
    print(parser.usage)
    print('[-] You must provide target host and port \n')
    sys.exit()
  else:
    t =threading.Thread(target=portScan, args=(targetHost,targetPort))
    t.start()
    
    
if __name__ == '__main__':
  main()
    
