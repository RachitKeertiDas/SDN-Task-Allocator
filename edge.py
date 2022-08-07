import json
import socket
import time
from struct import pack
from threading import Thread
from argparse import ArgumentParser
from datetime import datetime


tasks = {}
# def apply():
#     packet = json.dumps({'type':'ack','priority':150,'task':'add Host'})
#     dst = '10.255.255.255'
#     with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
#         print("Sending UDP Packet")
#         s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#         s.sendto(str.encode(packet),(dst,1900))

def request(task,description,port):
    now = datetime.now()
    now_str = now.strftime("%m/%d/%Y, %H:%M:%S")
    json_dict = {'type':'job','priority':150,'task':task,'task_desc':description,'time':now_str,'port':port}
    packet = json.dumps(json_dict)
    dst = '10.255.255.255'
    tasks[json_dict['time']] = 'unknown'
    print("Sending Broadcast for Job")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(str.encode(packet),(dst,1900))
    
    res = listen(port)
    print(f"{res} for {description}")
    return res


def listen(port):
    dst = '10.255.255.255'
    while(True):
        print('waiting')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("",port))
            # s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            data, addr = s.recvfrom(1024)
            str_data = data.decode()
            print(str_data, addr)
        try:
            json_data = json.loads(str_data)
            #busy(json_data['time'])
            time_status = tasks.get(json_data['time'])
            time_status = json_data["result"]
            break
        except:
            continue
    return json_data["result"]


# def exit():
#     packet = json.dumps({'type':'nak','priority':150,'task':'del Host'})
#     dst = '10.255.255.255'
#     with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
#         print("Sending UDP Packet for Exit")
#         s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#         s.sendto(str.encode(packet),(dst,1900))

if __name__ == '__main__':
    t1 = Thread(target=request,args=('prime_check',(41467,200,10000),12343))
    t2 = Thread(target=request,args=('prime_check',(41467,20000,30000),51412))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    print('My work is done')