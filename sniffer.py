import pyshark
import argparse
import matplotlib.pyplot as plt
import numpy as np
import time
from time import mktime
from datetime import datetime
import matplotlib.dates as mdates


class userData:
    """ contains info per tracked user"""
    #constructor
    def __init__(self, ip):
        self.ip = ip
        self.time_stamp = []
        self.bytes_rcvd_per_sec = []
        self.bytes_sent_per_sec = []

def shift_left(a_list):
    a_list.append(a_list.pop(0)) #rotate list
    a_list[-1] = 0 # zero last item

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
             only_summaries=True, monitor_mode=True)

    user_list = []    #list of packetData objects
    for ip in args.list_of_IP:
        user_list.append(userData(ip))

    sniff_duration = 2  # sniffing time

    #plotter initialization
    plt.ion()
    fig = plt.figure(figsize=(10,5))
    graph = fig.add_subplot(111)
    window_size = int(60*5/sniff_duration) # 5 minutes
    #window_size =  5# test
    y_default = 100     #when the y-values inside the window < y_default, the y-axis maximum = y_default (i.e. minimum y_axis range)
    #graph.axis([0, window_size+100, 0, y_default])  #setting the initial plot dimensions

    time_now = datetime.fromtimestamp(mktime(time.localtime()))
    for user in user_list:  #initialize/reset, +1 because 0 @ 0th place
        user.bytes_rcvd_per_sec.extend([0]*window_size)
        user.bytes_sent_per_sec.extend([0]*window_size)
        user.time_stamp.extend([time_now]*window_size)
    #start_time = time.monotonic()
    try:
        while True:
            for user in user_list:
                shift_left(user.bytes_rcvd_per_sec)
                shift_left(user.bytes_sent_per_sec)
                shift_left(user.time_stamp)

            #relative_start_time = time.monotonic()
            cap.sniff(timeout=sniff_duration)
            #delta_time = time.monotonic() - relative_start_time
            captured_packets = cap._packets
            for pkt in captured_packets: #iterate through all sniffed packet
                for user in user_list:  #iterate through user user_list
                    if user.ip == pkt.destination:
                        user.bytes_rcvd_per_sec[-1] += int(pkt.length)
                    elif user.ip == pkt.source:
                        user.bytes_sent_per_sec[-1] += int(pkt.length)
            time_now = datetime.fromtimestamp(mktime(time.localtime()))
            for user in user_list: #get time average
                user.bytes_rcvd_per_sec[-1] /= sniff_duration#delta_time
                user.bytes_sent_per_sec[-1] /= sniff_duration#delta_time
                user.time_stamp[-1] = time_now
                # print('user: ',user.ip)
                # print('rcvd: ',user.bytes_rcvd_per_sec)
                # print('sent: ',user.bytes_sent_per_sec)
            #UPDATE PLOT
            graph.clear()   #clear the plot every iteration to give way to the new curves
            y_max = 0
            for user in user_list:
                graph.plot(mdates.date2num(user.time_stamp), user.bytes_sent_per_sec, label=user.ip + ' (sent)')
                graph.plot(mdates.date2num(user.time_stamp), user.bytes_rcvd_per_sec, label=user.ip + ' (recv)')
                y_max = max(user.bytes_sent_per_sec + user.bytes_rcvd_per_sec + [y_default] + [y_max])  #y_max = max(sent or received bytes or y_default)
                plt.ylim(0, y_max + int(0.1*y_max))

            plt.title('Wifi Usage per IP')# please add plot title here
            plt.xlabel('Time')
            plt.ylabel('Bytes per second')
            plt.grid()
            plt.gcf().autofmt_xdate()

            graph.legend(loc='center left', bbox_to_anchor=(0.9, 0.5),fontsize='small')
            graph.xaxis.set_major_locator(mdates.MinuteLocator())
            graph.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            graph.xaxis.set_minor_locator(mdates.SecondLocator(interval=sniff_duration))

            fig.canvas.draw()
            plt.pause(0.001) # needed to be able to see plot

            cap.clear()

    except KeyboardInterrupt:
        print('\nExiting...') #better yata if i-exit na lang yung window
