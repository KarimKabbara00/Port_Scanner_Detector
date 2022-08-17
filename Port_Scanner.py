import socket
import time

# scans for open tcp ports
def tcp_scanner(port, target):
    # create a socket, connect to it given the ip and port. Close the port.
    try:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        tcp_sock.connect((target, port))
        tcp_sock.close()
        return True

    # if it cannot connect, return false.
    except:
        return False


# scan for open UDP ports
def udp_scanner(target, port):
    try:

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(2.0)

        udp_sock.sendto(bytes("NOTHING", "utf-8"), (target, port))  # Send a UDP packet to the IP and port of the target
        response, addr = udp_sock.recvfrom(1024)  # If an ICMP message comes back, port is closed or firewalled
        if response != None:
            return True
        return False

    except:
        print('no response from udp port {}. Port may be open but not responding.'.format(port))


def main():
    wait_time = 1 # 0.001 -- 0.5 -- 1 -- 5 -- 10
    target = input("[+] Enter Target IP: ")  # accept user input

    # call the TCP scanner function using the given ip and use ports 1 through 1024
    for portNumber in range(1, 1024):
        if tcp_scanner(portNumber, target):
            print('[*] Port', portNumber, '/tcp', 'is open')
        time.sleep(wait_time)

    # call the UDP scanner function using the given ip and use ports 1 through 1024
    for portNumber in range(1, 1024):
        if udp_scanner(target, portNumber):
            print('[*] Port', portNumber, '/udp', 'is open')
        time.sleep(wait_time)


if __name__ == "__main__":
    main()
