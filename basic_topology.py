import socket
import pdb
import time
from mininet.topo import Topo

class topology(Topo):
    def __init__(self, host_count=3):
        Topo.__init__(self)

        # Adding hosts and switches
        S1 = self.addSwitch('s1',mode='secure')
        S2 = self.addSwitch('s2')

        H11 = self.addHost('h11')
        H12 = self.addHost('h12')
        H21 = self.addHost('h21')
        H22 = self.addHost('h22')

        E1 = self.addHost('E1')
        
        SwitchList = (S1,S2)
        self.sl = SwitchList
        self.addLink(E1,S1)
        self.addLink(H11,S1)
        self.addLink(H12,S1)
        self.addLink(H21,S2)
        self.addLink(H22,S2)
        self.addLink(S1,S2)
            
    def addnewhost(self):
        h_n = self.addHost(f'h1{self.num_hosts}')
        self.num_hosts += 1
        self.addLink(h_n, self.sl[0])
        pass

custom = topology()
topos = {'mytopo':(lambda: custom)}
