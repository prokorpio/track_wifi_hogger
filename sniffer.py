import pyshark
import argparse
import matplotlib.pyplot as plt
import numpy as np
import time

class userData:
    """ contains info per tracked user"""
    #constructor
    def __init__(self, ip):
        self.ip = ip
        self.time_stamp = []
        self.bytes_rcvd_per_sec = []
        self.bytes_sent_per_sec = []


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', \
                        help="network interface to listen to, i.e. 'en0'")
    parser.add_argument("list_of_IP", nargs='+', \
                        help="space separated IP's to track")

    args = parser.parse_args()

    for idx, ip in enumerate(args.list_of_IP):
        if idx == 0:
            bpf_filter = 'host ' + args.list_of_IP[0]
        else:
            bpf_filter = bpf_filter + ' or host ' + ip

    print('Tracking: ')
    for ip in args.list_of_IP:
        print('\t ',ip)

    # setup packet sniffer
    cap = pyshark.LiveCapture(interface=args.interface, bpf_filter=bpf_filter, \
             only_summaries=True, monitor_mode=False)

    user_list = []    #list of packetData objects
    for ip in args.list_of_IP:
        user_list.append(userData(ip))

    sniff_duration = 3  # 3-second sniffing
    max_iter_count = 5 # end tracking after this much iterations
    for user in user_list:  #initialize, start at all zero
        user.bytes_rcvd_per_sec.append(0)
        user.bytes_sent_per_sec.append(0)
        user.time_stamp.append(0)

    for iter_count in range(1,max_iter_count+1):
        for user in user_list: #extend lists for each sniffing
            user.bytes_rcvd_per_sec.append(0)
            user.bytes_sent_per_sec.append(0)
        start_time = time.monotonic()
        cap.sniff(timeout=sniff_duration)
        delta_time = time.monotonic() - start_time
        start_time = time.monotonic()
        captured_packets = cap._packets
        print('Iteration: ', iter_count)
        print('Sniff time: ',delta_time)
        for pkt in captured_packets: #iterate through all sniffed packet
            for user in user_list:  #iterate through user user_list
                if user.ip == pkt.destination:
                    user.bytes_rcvd_per_sec[iter_count] += int(pkt.length)
                elif user.ip == pkt.source:
                    user.bytes_sent_per_sec[iter_count] += int(pkt.length)

        for user in user_list: #get time average
            user.bytes_rcvd_per_sec[iter_count] /= delta_time
            user.bytes_sent_per_sec[iter_count] /= delta_time
            user.time_stamp.append(user.time_stamp[-1] + delta_time)
        #UPDATE PLOT
        cap.clear()

        for user in user_list:
            print('Loop Time: ',time.monotonic()-start_time)
            print('IP: ',user.ip)
            print('\trcvd/s: ',user.bytes_rcvd_per_sec)
            print('\tsent/s: ',user.bytes_sent_per_sec)
            print('\ttime: ',user.time_stamp)
