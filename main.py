from scapy.all import *
from scapy.layers import *
import argparse
import os
import csv
from colorama import Fore, Back, Style

TcpStat = {}
UdpStat = {}
Stat = {}



if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-d', '--dir', help='Pcap file Directory.', required=True)
    arg_parser.add_argument('-o', '--output', help='Result Output File.', default=os.path.join(os.path.split(os.path.realpath(__file__))[0], 'output.csv'))
    cmd_args = arg_parser.parse_args()

    print(Back.YELLOW, Fore.WHITE, 'Get files from Directory: ' + cmd_args.dir, Style.RESET_ALL)
    # Get Files from  Directory
    for f in os.listdir(cmd_args.dir):
        if(f.endswith('.pcap') or f.endswith('.pcapng')):  # Check 
            file_path = os.path.join (cmd_args.dir, f)
            print(Fore.YELLOW, 'Scanning Pcap File: ', file_path, Style.RESET_ALL)
            # Read Pcap File
            pkts = rdpcap("/home/george/pcap/http_number_test.pcapng")
            # Traverse Packet file in Pcap File
            for pkt in pkts:
                if pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer('TCP'):
                    tuple4 = pkt[IP].src + ':' + str(pkt['TCP'].sport) + ' --> ' + pkt[IP].dst + ':' + str(pkt['TCP'].dport)
                    if tuple4 not in Stat:  
                        Stat[tuple4] = 0
                    Stat[tuple4] += 1
                elif pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer('UDP'):
                    tuple4 = pkt[IP].src + ':' + str(pkt['UDP'].sport) + ' --> ' + pkt[IP].dst + ':' + str(pkt['UDP'].dport)
                    if tuple4 not in Stat:  
                        Stat[tuple4] = 0
                    Stat[tuple4] += 1

    # Show Statistic
    # print(TcpStat)
    # print(UdpStat)

    # Write Data to file
    of = open(cmd_args.output, 'w')
    for key, value in Stat.items():
        of.write(key + ',' + str(value) + '\n')
    of.close()
    print(Fore.WHITE, Back.GREEN, 'Program Terminated, Data was Writen in', Back.YELLOW, cmd_args.output, Style.RESET_ALL)
