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
    parser.add_argument("list_of_IP", nargs='+', \
                        help='space separated IPs to track')

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
    cap = pyshark.LiveCapture(interface='en0', bpf_filter=bpf_filter, \
             only_summaries=True, monitor_mode=False)
    cap.sniff(timeout=0) #cap.sniff() to sniff forever (in a thread)

    user_list = []    #list of packetData objects
    for ip in args.list_of_IP:
        user_list.append(userData(ip))


    sniff_duration = 3  # 3-second sniffing
    iter_count = 0      # 1 sniff duration is one iter count
    max_iter_count = 60 # end tracking after this much iterations
    for user in user_list:  #initialize
        user.bytes_rcvd_per_sec.append(0)
        user.bytes_sent_per_sec.append(0)
        user.time_stamp.append(0)
    start_time = time.monotonic()
    for pkt in cap: #iterate through sniffed packet
        for user in user_list:  #iterate through user user_list
            if user.ip == pkt.destination:
                user.bytes_rcvd_per_sec[iter_count] += int(pkt.length)
                print('pkt rcvd: ',int(pkt.length))
            elif user.ip == pkt.source:
                user.bytes_sent_per_sec[iter_count] += int(pkt.length)
                print('pkt sent: ',int(pkt.length))

        delta_time = time.monotonic() - start_time
        if delta_time >= sniff_duration:
            for user in user_list:
                user.bytes_rcvd_per_sec[iter_count] /= delta_time
                user.bytes_sent_per_sec[iter_count] /= delta_time
                user.time_stamp[iter_count] = delta_time
            #update plot
            iter_count += 1
            print('iteration: ', iter_count)
            for user in user_list:
                print('IP: ',user.ip)
                print('\trcvd/s: ',user.bytes_rcvd_per_sec)
                print('\tsent/s: ',user.bytes_sent_per_sec)
                print('\ttime: ',user.time_stamp)
                user.bytes_rcvd_per_sec.append(0)
                user.bytes_sent_per_sec.append(0)
                user.time_stamp.append(0)
            if iter_count == max_iter_count:
                break   # will stop iterating through sniffed packets
            start_time = time.monotonic()
