import socket
import struct
from datetime import datetime
from threading import Thread


def mac_format(mac):
    mac = map('{:02x}'.format, mac)
    return ':'.join(mac).upper()


def ipv4_format(address):
    return '.'.join(map(str, address))


# ethernet header
def ethernet_dissect(ethernet_data):
    dest_mac, src_mac, protocol = struct.unpack('!6s6sH', ethernet_data[:14])
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]


def ipv4_dissect(ip_data):
    ip_protocol, source_ip, target_ip = struct.unpack('!9x B 2x 4s 4s', ip_data[:20])
    return ip_protocol, ipv4_format(source_ip), ipv4_format(target_ip), ip_data[20:]


def tcp_dissect(transport_data):
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port


def remove_old_scans(first_contact_table):
    # gets current time
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")

    for i in first_contact_table:

        time = i[3]
        time_diff = datetime.strptime(current_time, '%H:%M:%S') - datetime.strptime(time, '%H:%M:%S')
        time_diff_formatted = (int(str(time_diff)[2] + str(time_diff)[3]))

        if time_diff_formatted >= 5:
            first_contact_table.remove(i)

    with open("first_contact_list.txt", 'w') as file:
        file.writelines('\t'.join(str(j) for j in i) + '\n' for i in first_contact_table)

    return first_contact_table


def get_fanout_rate(first_contact_table):
    # stores unique source ips
    unique_source_ips = []
    for i in first_contact_table:
        if i[0] not in unique_source_ips:
            unique_source_ips.append(i[0])

    for i in unique_source_ips:
        times = []  # used to get first and last scan time of a given source ip
        counter = 0  # counts how many scans for a given source ip
        for j in first_contact_table:
            if i == j[0]:
                counter += 1
                times.append(j[3])

        time_difference = str(datetime.strptime(times[-1], '%H:%M:%S') - datetime.strptime(times[0], '%H:%M:%S'))
        h, m, s = time_difference.split(':')
        time_diff_sec = int(h) * 3600 + int(m) * 60 + int(s)
        time_diff_mins = (int(h) * 3600 + int(m) * 60 + int(s)) / 60
        time_diff_5mins = (int(h) * 3600 + int(m) * 60 + int(s)) / 300

        if time_diff_sec > 0:
            fan_out_rate_sec = (counter / time_diff_sec) / time_diff_sec
            if fan_out_rate_sec >= 5:
                print("portscanner detected on source IP:", i)
                print("avg. fan-out per sec:", fan_out_rate_sec)
                print("reason: must be less than 5/sec")

        elif time_diff_mins > 0:
            fan_out_rate_min = (counter / time_diff_mins) / time_diff_mins
            if fan_out_rate_min >= 100:
                print("portscanner detected on source IP:", i)
                print("avg. fan-out per min:", fan_out_rate_min)
                print("reason: must be less than 100/min")

        elif time_diff_5mins > 0:
            fan_out_rate_5min = (counter / time_diff_5mins) / time_diff_5mins
            if fan_out_rate_5min >= 300:
                print("portscanner detected on source IP:", i)
                print("avg. fan-out per 5 min:", fan_out_rate_5min)
                print("reason: must be less than 300/5min")


def sniff_packets():

    # capture packets
    packets = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    print("looking for port scanners...")

    first_contact_table = []
    while True:
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        tmp_list = []  # holds info for one captured packet
        ethernet_data, address = packets.recvfrom(65536)
        dest_mac, src_mac, protocol, data = ethernet_dissect(ethernet_data)

        if protocol == 8:
            ip_protocol, src_ip, dest_ip, transport_data = ipv4_dissect(data)

            # TCP
            if ip_protocol == 6:
                src_port, dest_port = tcp_dissect(transport_data)

                # stores info
                tmp_list.append(src_ip)
                tmp_list.append(dest_ip)
                tmp_list.append(dest_port)
                tmp_list.append(current_time)

        if tmp_list:
            first_contact_table.append(tmp_list)

        first_contact_table = remove_old_scans(first_contact_table)
        get_fanout_rate(first_contact_table)


def main():
    t1 = Thread(target=sniff_packets)
    t1.start()


if __name__ == '__main__':
    main()
