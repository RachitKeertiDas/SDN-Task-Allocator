# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from matplotlib.style import available
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, ipv6, udp
from ryu.lib.packet import ether_types
import json 
from datetime import datetime
from threading import Thread
import time

class Distributed_Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Distributed_Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.resources = {}
        self.t1 = Thread(target=self.checking,args=())
        self.task_pos = {}

    def allocate_task(self,dpid,datapath,msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        old_pkt = packet.Packet(msg.data)
        new_pkt = packet.Packet()
        
        
        #print(f"Length of Payload: {len(old_pkt[-1])}")
        data = b'Hello Data'
        diff = len(data) - len(old_pkt[-1])
        #old_pkt[-1] = data
        data = old_pkt[-1]

        for proto in old_pkt.protocols:
            print("Proto",proto)
    

        print(self.resources.items())
        for key,value in self.resources.items():
            if value['available']:
                print("Allocated BEEP BOOP")
                #print(key)
                #print("Length of Ipv4 Segment",old_pkt.get_protocols(ipv4.ipv4)[0].dst)

                old_pkt.get_protocols(ethernet.ethernet)[0].dst = key
                old_pkt.get_protocols(ipv4.ipv4)[0].dst = value['ip']
                old_pkt.get_protocols(ipv4.ipv4)[0].total_length += diff
                old_pkt.get_protocols(udp.udp)[0].total_length += diff
                old_pkt.get_protocols(udp.udp)[0].csum = 0x0000

                ether_proto = ethernet.ethernet(ethertype=2048, dst=key, src=old_pkt.get_protocols(ethernet.ethernet)[0].src)
                ip_proto = ipv4.ipv4(src=old_pkt.get_protocols(ipv4.ipv4)[0].src, 
                    dst=value['ip'],
                    identification=old_pkt.get_protocols(ipv4.ipv4)[0].identification,
                    flags=old_pkt.get_protocols(ipv4.ipv4)[0].flags,
                    proto=old_pkt.get_protocols(ipv4.ipv4)[0].proto
                )
                udp_proto = udp.udp(src_port=old_pkt.get_protocols(udp.udp)[0].src_port,dst_port=old_pkt.get_protocols(udp.udp)[0].dst_port)
                new_pkt.add_protocol(ether_proto)
                new_pkt.add_protocol(ip_proto)
                new_pkt.add_protocol(udp_proto)
                new_pkt.add_protocol(data)
                new_pkt.serialize()

                for proto in new_pkt.protocols:
                    print("New Proto",proto)
                print("Length of Ipv4 Segment",old_pkt.get_protocols(ipv4.ipv4)[0].dst)

                if key in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][key]
                    #out_port = ofproto.OFPP_FLOOD

                    print("I Know how to get there", out_port)
                else:
                    out_port = ofproto.OFPP_FLOOD
                    #print("Idk, flooding", out_port)

                actions = [parser.OFPActionOutput(out_port)]

                if out_port != ofproto.OFPP_FLOOD:
                    print('OFPP Controller: ', ofproto.OFPP_CONTROLLER)
                    match = parser.OFPMatch(in_port=msg.match['in_port'], eth_dst=key)
                    print('Match: ', match)
                    print('buffer_id',msg.buffer_id)
                    self.add_flow(datapath, 1, match, actions,buffer_id=msg.buffer_id)

                # print("Decoded Message Data", msg.data)
                # data = str.encode("Hello Data "+key)
                # # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                #     # data = msg.data
                # new_pkt = packet.Packet()
                # print('Out Port: ', out_port)

                # new_pkt = packet.Packet()
                # new_pkt.add_protocol(udp.udp())
                # new_pkt.serialize(data)
                # # new_pkt.add_protocol()
                # print(type(data))
                
                # print("Data in allocate_taks: ",data)
                #old_pkt.serialize()
                out = parser.OFPPacketOut(buffer_id =msg.buffer_id,datapath=datapath, actions=actions, data=new_pkt,in_port=msg.match['in_port'])
                # print("Type pf pu",type(out))
                datapath.send_msg(out)
                break



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def checking(self,threshould=20,gap = 10):
        while(True):
            time.sleep(gap)
            for key,v in self.resources.items():
                if((datetime.now()-v['time']).seconds > threshould):
                    self.resources.pop(key)

    def add_flow(self, datapath, priority, match, actions,buffer_id=4294967295):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,buffer_id=buffer_id)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        in_port = msg.match['in_port']
        print("Input",in_port)


        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # We only handle IPv4 packets for now
        temp = False
        try:
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            print(pkt)
            temp = True
        except:
            #ip = pkt.get_protocol(ipv6.ipv6[0])
            temp = False
            #return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        if temp is True:
            src_ip = ip.src
        #print(f"Source:{src}, IP Source: {src_ip}, Dest: {dst}, Packet Content:{pkt}")
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
        if type(pkt[-1]) == type(b'Iam in'):
            print(type(pkt[-1]))

            data = json.loads(pkt[-1].decode())
        else:
            data = {}
            data['type'] = "Nah"

        print(data,'\n\n')
        if(data['type'] == 'ack'):
            new_host = {src:{'available':True, 'ip':  src_ip,'time':datetime.now()}}
            self.resources.update(new_host)
            print(self.resources)
            print(self.mac_to_port)
            print("found new entry or someone is still alive")
        elif (data['type'] == 'busy'):
            new_host = {src:{'available':False, 'ip':  src_ip,'time':data['time']}}
            self.resources.update(new_host)
        elif(data['type'] == 'nak'):
            self.resources.pop(src, None)
            print(self.resources)
            print("Deleted new entry")
        elif(data['type'] == 'result'):
            new_host = {src:{'available':True, 'ip':  src_ip,'time':data['time']}}
            self.resources.pop(src, None)
            print(self.resources)
            print("Deleted new entry")
        elif(data['type'] == 'job'):
            T_allocate = Thread(target=self.allocate_task(dpid,datapath,msg))
            T_allocate.start()
            print('GOOOOOOOOO')
            

        # learn a mac address to avoid FLOOD next time.
        if dst == "10.255.255.255":
            print("New Task recieved")


        #print(f"Self. M2P {self.mac_to_port}")

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
