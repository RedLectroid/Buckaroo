import sys
import argparse
import os
from progressbar import ProgressBar
import subprocess

parser = argparse.ArgumentParser(description='bulk nmap scan from imput file')
parser.add_argument('-i','--input',type=str,action='store',required=True,help='Input file containing list of IPs to be scanned')

args=parser.parse_args()

def file_len(fname):
  p = subprocess.Popen(['wc', '-l', fname], stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE)
  result, err = p.communicate()
  if p.returncode != 0:
      raise IOError(err)
  return int(result.strip().split()[0])

def do_scan(IP):

  tmpIP = IP

  if tmpIP != "":
    ipparts = tmpIP.split(".")
    subdir = "sub"+ipparts[2]

    if not os.path.exists(subdir):
      os.mkdir(subdir)

    f = open(subdir+"/"+ipparts[3]+".txt",'w')
    output = subprocess.check_output("nmap -v -T3 -A -p- "+IP,shell=True)
    f.write(output) 
    print "Finished scanning " + IP

if __name__ == "__main__":

  IPcount = file_len(args.input)
  print "Scanning %s hosts. Sit back and relax\n" %IPcount

  with open (args.input,'r') as f:
    lines = f.readlines()

  pbar = ProgressBar()
  for item in pbar(lines):
    item = item.rstrip()
    do_scan(item)
  print "Done scanning the %s hosts. Enjoy the results!\n" %IPcount
