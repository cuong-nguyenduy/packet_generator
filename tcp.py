'''
    Raw sockets on Linux
     
    Silver Moon (m00n.silv3r@gmail.com)
'''

# some imports
import time
import argparse
import random
import socket, sys, os
from struct import *


# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s += s >> 16

    # complement and mask to 4 byte short
    s = ~s & 0xffff

    return s


# Constructing the packet
def construct_tcp(src, dst, src_port, dst_port):
    packet = ''

    source_ip = src
    dest_ip = dst

    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 54321  # Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(source_ip)  # Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
                     ip_saddr, ip_daddr)

    # tcp header fields
    tcp_source = src_port  # source port
    tcp_dest = dst_port  # destination port
    tcp_seq = random.randrange(1 << 32)
    tcp_ack_seq = 0
    tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
    # tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)  # maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window,
                      tcp_check, tcp_urg_ptr)

    user_data = 'Hello, how are you'

    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length);
    psh = psh + tcp_header + user_data;

    tcp_check = checksum(psh)
    # print tcp_checksum

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                      tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)

    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header + user_data

    return packet


def main(p):
    random.seed()

    p.add_argument("-s", help="Source IP address", default='127.0.0.1')
    p.add_argument("-d", help="Destination IP address", default='127.0.0.1')
    p.add_argument("-sp", help="Source TCP/UDP port", default=12345, type=int)
    p.add_argument("-dp", help="Destination TCP/UDP port", default=80, type=int)
    p.add_argument("-i", help="Interval, in milliseconds", default=1000, type=int)
    p.add_argument("-c", help="Number of packets being sent", default=5, type=int)
    p.add_argument("-v", help="Enable verbosity", default=0, type=int)

    args = p.parse_args()
    print(args)

    # Create a raw socket
    try:#
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error, msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    # tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
    # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet = construct_tcp(args.s, args.d, args.sp, args.dp)
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

    start_time = time.time()
    for i in range(args.c):
        if args.v == 0:
            sys.stdout.write('!')
            if i % 100 == 99:
                print('')
        elif args.v == 1:
            print("Sending packet " + str(i + 1) + ": " + \
                  args.s + "/" + str(args.sp) + " --> " + args.d + "/" + str(args.dp))

        s.sendto(packet, (args.d, 0))
        time.sleep(args.i/1000.0)
    print('\nCompleted! Send ' + str(args.c) + " packet(s) took " + str(time.time() - start_time) + " seconds!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    main(parser)
