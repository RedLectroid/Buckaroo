import nmap
import sys
import argparse
import os
import subprocess

parser = argparse.ArgumentParser(description='bulk nmap scan from imput file')
parser.add_argument('-i','--input',type=str,action='store',required=True,help='Input file containing list of IPs to be scanned')
parser.add_argument('-p',action='store_true',required=False,help='Print the scans as they come in')
args=parser.parse_args()

def file_len(fname):
  p = subprocess.Popen(['wc', '-l', fname], stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE)
  result, err = p.communicate()
  if p.returncode != 0:
    raise IOError(err)
  return int(result.strip().split()[0])

def do_scan(target):
  
  nm = nmap.PortScanner()
  nm.scan(target,'1-65535')
  write_scan(nm,target)
  if args.p !=False:
    print_scan(nm,target)

def print_scan(nmapScan,host):

  print('------------------%s------------------\n' %host)

  for proto in nmapScan[host].all_protocols():
      lport = list(nmapScan[host][proto].keys())
      lport.sort()
      for port in lport:

        print('Port %d' %port)
        print('-----------')
        print('Service:\t ' + nmapScan[host]['tcp'][port]['name'])
        print('Version:\t ' + nmapScan[host]['tcp'][port]['version'])
        print('Product:\t ' + nmapScan[host]['tcp'][port]['product'] + '\n')
  print('----------------------------------------------------\n')

def write_scan(nmapScan, host):

  tmp_host = host
  if tmp_host != "":
    ipparts = tmp_host.split(".")
    subdir = "sub"+ipparts[2]
    if not os.path.exists(subdir):
      os.mkdir(subdir)
    
    f = open(subdir+"/"+ipparts[3]+".txt",'w')
    
    for proto in nmapScan[host].all_protocols():
      f.write('----------\n')
      lport = list(nmapScan[host][proto].keys())
      lport.sort()
      for port in lport:
        f.write('%d' %port + ' :\t ' + nmapScan[host]['tcp'][port]['name'] + '\t ' + nmapScan[host]['tcp'][port]['product'] + '\t ' + nmapScan[host]['tcp'][port]['version'] + '\n')
    f.write('----------------------------------------------------\n')

    print "Done scanning "+host

if __name__ == "__main__":

  IPcount = file_len(args.input)
  print "Scanning %s hosts. Sit back and relax\n" %IPcount

  with open (args.input,'r') as f:
    lines = f.readlines()

  for item in lines:
    item = item.replace('\n','')
    do_scan(item) 

  print "Done scanning the %s hosts. Enjoy the results\n" %IPcount
