import pyshark
import argparse

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

    cap = pyshark.LiveCapture(interface='en0', bpf_filter=bpf_filter, \
             only_summaries=True, monitor_mode=True)
    cap.sniff(packet_count=10) #cap.sniff() to sniff forever (in a thread)

    bytes_received = {}
    bytes_sent = {}
    for ip in args.list_of_IP:
        bytes_received[ip] = 0;	#defines dictionary where key=IP, dict[key] = bytes[IP] = #bytes
        bytes_sent[ip] = 0;

    for pkt in cap:
        if pkt.destination in args.list_of_IP:
            bytes_received[pkt.destination] += int(pkt.length)
            print('rcvd: {}'.format(bytes_received))
        elif pkt.source in args.list_of_IP:
            bytes_sent[pkt.source] += int(pkt.length)
            print('sent: {}'.format(bytes_sent))
