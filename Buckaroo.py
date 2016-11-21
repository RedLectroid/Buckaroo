import sys
import argparse
import os
import subprocess

parser = argparse.ArgumentParser(description='bulk nmap scan from imput file')
parser.add_argument('-i','--input',type=str,action='store',required=True,help='Input file containing list of IPs to be scanned')
parser.add_argument('-p',action='store_true',required=False,help='Print the scans as they come in')

args=parser.parse_args()

#Counts number of IP addresses in IP list
def file_len(fname):
  p = subprocess.Popen(['wc', '-l', fname], stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE)
  result, err = p.communicate()
  if p.returncode != 0:
    raise IOError(err)
  return int(result.strip().split()[0])

def scanHTTP(port,host):

  if args.p != False:
    try:
      outputNikto = subprocess.check_output(['nikto','-h',host,'-p',str(port)])
    except:
      pass
    print outputNikto
    try:
      outputDirb = subprocess.check_output(['dirb','http://'+host+':'+str(port)])
    except:
      pass
    print outputDirb
  else:
    tmp_host = host
    if tmp_host != "":
      ipparts = tmp_host.split(".")
      subdir = "sub"+ipparts[2]
    
    fNikto = subdir+"/"+ipparts[3]+"NiktoPort%s.txt"%port
    try:
      print "Running Nikto on " + host + "on port " + port
      subprocess.check_output(['nikto','-h',host,'-p',str(port),'-o',fNikto]):
    except:
      pass
    print 'Done Nikto scan on ' + host + ' port %s'%port

    fDirb = subdir+"/"+ipparts[3]+"DirbPort%s.txt"%port
    try:
      print "Running Dirb on " + host + "on port " + port
      outputDirb = subprocess.check_output(['dirb','http://'+host+':'+str(port),'-o',fDirb])
    except:
      pass
    print 'Done Dirb scan on ' + host + ' port %s'%port


def checkPorts(file,host):

  wordsHTTP = ['tcp','open','http']
  f = open(file,'r')
  for line in f:
    if all(x in line for x in wordsHTTP):
      tmpString = line.split("/")
      port = tmpString[0]
      print "found http on port " + port + " on IP " + host
      scanHTTP(port,host)

def do_scan(host):

  if args.p != False:
    try:
      NmapScan = subprocess.check_output(['nmap','-v','-T3','-A','-p-',host])
      print NmapScan

    except:
      pass

  tmp_host = host
  if tmp_host != "":
    ipparts = tmp_host.split(".")
    subdir = "sub"+ipparts[2]
    if not os.path.exists(subdir):
      os.mkdir(subdir)
    fileName = subdir+"/"+ipparts[3]+"Nmap.txt"
    f = open(fileName,'w')

    try:
      NmapScan = subprocess.check_output(['nmap','-v','-T3','-A','-p-',host])
    except:
      pass

    f.write(NmapScan)
    checkPorts(fileName,host)
    print 'Done scanning '+ host

if __name__ == "__main__":

  IPcount = file_len(args.input)
  print "Scanning %s hosts. Sit back and relax\n" %IPcount

  with open (args.input,'r') as f:
    lines = f.readlines()

  for item in lines:
    item = item.replace('\n','')
    print 'Starting Nmap scan on ' + item
    do_scan(item) 

  print "Done scanning the %s hosts. Enjoy the results\n" %IPcount
