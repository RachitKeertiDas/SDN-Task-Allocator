import json
import socket
import time
from struct import pack
from threading import Thread
from argparse import ArgumentParser
from datetime import datetime

endpoint_addr = '127.0.0.1'

def apply():
    packet = json.dumps({'type':'ack','priority':150,'task':'add Host'})
    dst = '10.255.255.255'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        print("Sending UDP Packet")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(str.encode(packet),('10.255.255.255',2100))

def alive():
    for i in range(100):
        time.sleep(5)
        packet = json.dumps({'type':'ack','priority':150,'task':'I am here'})
        dst = '10.255.255.255'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(str.encode(packet),(dst,2100))

def listen():
    dst = '10.255.255.255'
    while(True):
        task_addr = ''
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("",1900))
            # s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            data, addr = s.recvfrom(1024)
            str_data = data.decode()
            print(str_data, addr)

        # Check if we got a valid job description
        
        json_data = json.loads(str_data)
        result_req_time = json_data.get('time')
        result_port = json_data.get('port')
        if result_req_time is None or result_port is None:
            continue
        print(str_data)
        task_addr = (addr[0],json_data['port'])

        busy(json_data['time'])
        if json_data["task"] == 'prime_check':
            num, start, end = json_data["task_desc"]
            prime_result = primality_check(num,start,end)
        packet = json.dumps({'type':'result','priority':150,'task':'prime_check', "time": json_data["time"], "result": prime_result})
        result(packet, task_addr)
        apply()
        

def primality_check(num, start, end):

    for i in range(start, end):
        if i == 1:
            continue
        if num%i == 0:
            return False
    return True

def busy(time_stamp):
    packet = json.dumps({'type':'busy','priority':100,'time':time_stamp})
    dst = '10.255.255.255'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        print("Sending UDP Packet for Busy")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(str.encode(packet),(dst,1900))

def result(packet, task_addr):
    # dst = '10.255.255.255'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        print("Announcing Result")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(str.encode(packet),(task_addr))

def exit():
    packet = json.dumps({'type':'nak','priority':150,'task':'del Host'})
    dst = '10.255.255.255'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        print("Sending UDP Packet for Exit")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(str.encode(packet),(dst,1900))

if __name__ == '__main__':
    apply()
    t1 = Thread(target=alive)
    t1.start()
    listen_thread = Thread(target=listen)
    listen_thread.start()
    print('My work is done')