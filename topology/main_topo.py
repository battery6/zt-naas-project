import sys
import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

class ZT_NaaS_Topo(Topo):
    def build(self):

        # --- Switches ---

        # User Network switch
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, failMode="secure", dpid='0000000000000001')

        # Admin Network switch
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, failMode="secure", dpid='0000000000000002')

        # Server Network switch
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, failMode="secure", dpid='0000000000000003')

        # Guest Network switch
        s4 = self.addSwitch('s4', cls=OVSKernelSwitch, failMode="secure", dpid='0000000000000004')

        # --- Routing ---

        # Central router
        r1 = self.addHost('r1')

        # Router links
        self.addLink(r1, s1)
        self.addLink(r1, s2)
        self.addLink(r1, s3)
        self.addLink(r1, s4)

        # --- TENANT 1, User Network ---
        h1_user = self.addHost('h1user', ip='10.0.1.11/24', mac='00:00:00:00:01:11')
        h2_user = self.addHost('h2user', ip='10.0.1.12/24', mac='00:00:00:00:01:12')
        h3_user = self.addHost('h3user', ip='10.0.1.13/24', mac='00:00:00:00:01:13')
        self.addLink(h1_user, s1)
        self.addLink(h2_user, s1)
        self.addLink(h3_user, s1)

        # --- TENANT 2, Admin Network ---
        h4_admin = self.addHost('h4admin', ip='10.0.2.11/24', mac='00:00:00:00:02:11')

        self.addLink(h4_admin, s2)

        # --- TENANT 3, Server Network ---
        h5_appserv = self.addHost('h5appserv', ip='10.0.3.11/24', mac='00:00:00:00:03:11')
        h6_dbserv = self.addHost('h6dbserv', ip='10.0.3.12/24', mac='00:00:00:00:03:12')

        self.addLink(h5_appserv, s3)
        self.addLink(h6_dbserv, s3)

        # --- TENANT 4, Guest Network ---
        h7_guest = self.addHost('h7guest', ip='10.0.4.11/24', mac='00:00:00:00:04:11')

        self.addLink(h7_guest, s4)

def configure_network(net):
    print("*** Konfigurerar nätverk (IP + Routing) ***")

    # Get devices
    r1 = net.get('r1')
    h1user = net.get('h1user')
    h2user = net.get('h2user')
    h3user = net.get('h3user')
    h4admin = net.get('h4admin')
    h5appserv = net.get('h5appserv')
    h6dbserv = net.get('h6dbserv')
    h7guest = net.get('h7guest')

    # Enable routing
    r1.cmd('sysctl -w net.ipv4.ip_forward=1')

    # Configure router interfaces
    r1.cmd('ip addr add 10.0.1.1/24 dev r1-eth0')
    r1.cmd('ip addr add 10.0.2.1/24 dev r1-eth1')
    r1.cmd('ip addr add 10.0.3.1/24 dev r1-eth2')
    r1.cmd('ip addr add 10.0.4.1/24 dev r1-eth3')

    # Configure default gateways
    h1user.cmd('ip route add default via 10.0.1.1')
    h2user.cmd('ip route add default via 10.0.1.1')
    h3user.cmd('ip route add default via 10.0.1.1')
    h4admin.cmd('ip route add default via 10.0.2.1')
    h5appserv.cmd('ip route add default via 10.0.3.1')
    h6dbserv.cmd('ip route add default via 10.0.3.1')
    h7guest.cmd('ip route add default via 10.0.4.1')

    # Start servers
    h5appserv.cmd('python3 /home/philip/zt-naas-project/services/http_server.py > /home/philip/zt-naas-project/logs/h4_app.log 2>&1 &')
    h5appserv.cmd('python3 /home/philip/zt-naas-project/services/https_server.py > /home/philip/zt-naas-project/logs/h4_app.log 2>&1 &')
    h5appserv.cmd('python3 /home/philip/zt-naas-project/services/ssh_server.py > /home/philip/zt-naas-project/logs/h4_app.log 2>&1 &')
    h6dbserv.cmd('python3 /home/philip/zt-naas-project/services/ssh_server.py > /home/philip/zt-naas-project/logs/h5_db.log 2>&1 &')
    h6dbserv.cmd('python3 /home/philip/zt-naas-project/services/db_server.py > /home/philip/zt-naas-project/logs/h5_db.log 2>&1 &')
    h6dbserv.cmd('python3 /home/philip/zt-naas-project/services/db_tls_server.py > /home/philip/zt-naas-project/logs/h5_db.log 2>&1 &')

    # Distribute certificates
    h1user.cmd("cp /home/philip/zt-naas-project/certs/ca.crt /tmp/ca.crt")
    h4admin.cmd("cp /home/philip/zt-naas-project/certs/ca.crt /tmp/ca.crt")

def wait_for_servers(net):
    h5 = net.get("h5appserv")
    h6 = net.get("h6dbserv")

    for _ in range(20):
        h5_ports = h5.cmd("ss -ltn")
        h6_ports = h6.cmd("ss -ltn")

        if ":80" in h5_ports and ":443" in h5_ports and ":5432" in h6_ports:
            return True

        time.sleep(0.2)

    print("Warning: servers did not appear ready")
    print(h5.cmd("ss -ltn"))
    print(h6.cmd("ss -ltn"))
    return False

def run():

    topo= ZT_NaaS_Topo()
    print("*** Startar Mininet med Controller ***")
    net = Mininet(topo=topo, controller=RemoteController, waitConnected=True)

    net.start()
    configure_network(net)
    wait_for_servers(net)
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('debug')
    run()
