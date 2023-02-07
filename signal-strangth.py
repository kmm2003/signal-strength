import pcap
import dpkt
import binascii
import argparse
import os
import time

global pkt

def mac_parse(mac):
  global pkt
  mac = bytearray(mac).decode()
  if mac == "ffffffffffff":
      return 0
  mac = f"{mac[0:2]}:{mac[2:4]}:{mac[4:6]}:{mac[6:8]}:{mac[8:10]}:{mac[10:12]}"
  return mac

def essid_parse(pkt):
  essid=''
  for i in [48,60]:
    pkt = bytearray(pkt)
    flag = pkt[i]
    if flag == 0:
        leng = pkt[i+1]
        for j in range(i+2,i+2+leng):
            essid = essid+chr(pkt[j])
        if essid[0] == '\u0000':
            return "This is Hidden API"
        return essid

def print_log(mac, essid, antennaSignal):
  os.system("clear")
  print("MAC\t\t\tAntennaSignal\tessid\n")
  print(f"{mac}\t",end='')
  print(f"{antennaSignal}\t\t",end='')
  print(f"{essid}\n",end='')
  print()
  
def sniffer(interface, mac):
  global pkt
  sniff_pkt = pcap.pcap(name = interface, promisc = True, immediate = True, timeout_ms = 50)
  for ts, pkt in sniff_pkt:
    try:
      tap = dpkt.radiotap.Radiotap(pkt)
      signal_ssi = -(256-tap.ant_sig.db)        # Calculate signal strength
      t_len = binascii.hexlify(pkt[2:3])    # t_len field indicates the entire length of the radiotap data, including the radiotap header.
      t_len = int(t_len,16) # Convert to decimal
      if t_len == 24:
        wlan = dpkt.ieee80211.IEEE80211(pkt[t_len:])
        tsaddr = mac_parse(binascii.hexlify(pkt[t_len + 10 : t_len + 16])) # transmitter addr parsing
        essid = essid_parse(pkt) # essid parsing
        if mac == tsaddr: # compare essid & user input
          print_log(mac, essid, signal_ssi)
    except:
      pass

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("interface")
  parser.add_argument("mac",metavar="MAC")
  args = parser.parse_args()
  sniffer(args.interface, args.mac)
