import socket
import os

#listening host
HOST = '0.0.0.0'

#possibly autokickoff other scans based on other results

def main():
    if os.name == 'nt':
        socket_protocol = SOCKET.IPPROTO_IP
    else:
        socket_protocol =  socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST,0))

    #grab ip header
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print(sniffer.recvfrom(65565))

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

if __name__ == '__main__':
    main()

