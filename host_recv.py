import json
import socket
import time
from struct import pack
from threading import Thread


def alive():
    dst = '10.255.255.255'
    while(True):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("",1900))
            # s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            data, addr= s.recvfrom(1024)
            print(data.decode(), addr)


if __name__ == '__main__':
    # apply()
    alive()
    # t1 = Thread(target=alive)
    # t1.start()
    # print('My work is done')
