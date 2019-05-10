import pyshark
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("listOfIP", nargs='+', \
                        help='space separated IPs to track')

    args = parser.parse_args()

    for idx, ip in enumerate(args.listOfIP):
        if idx == 0:
            bpfFilter = 'host ' + args.listOfIP[0]
        else:
            bpfFilter = bpfFilter + ' or host ' + ip
    #print info to track

    cap = pyshark.LiveCapture(interface='en0', bpf_filter=bpfFilter, \
             only_summaries=True, monitor_mode=True)
    cap.sniff(packet_count=10) #cap.sniff() to sniff forever (in a thread)

    bytes_received = {}
    bytes_sent = {}
    for ip in args.listOfIP:
    	bytes_received[ip] = 0;	#defines dictionary where key=IP, dict[key] = bytes[IP] = #bytes
    	bytes_sent[ip] = 0;

    for pkt in cap:
    	if pkt.destination in args.listOfIP:
            bytes_received[pkt.destination] += int(pkt.length)
            print('rcvd: {}'.format(bytes_received))
    	elif pkt.source in args.listOfIP:
            bytes_sent[pkt.source] += int(pkt.length)
            print('sent: {}'.format(bytes_sent))

    # cap = pyshark.LiveCapture(interface='en0', bpf_filter='host 10.11.16.58', \
    #         only_summaries=True, monitor_mode=True)
    # cap.sniff(packet_count=10) #cap.sniff() to sniff forever (in a thread)
    #
    # for pkt in cap:
    #     print(pkt)
