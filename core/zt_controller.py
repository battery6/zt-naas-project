from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, icmp, tcp
from ryu.app.wsgi import WSGIApplication

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPERIMENTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, EXPERIMENTS_DIR)

from policy.policies import POLICIES, ALLOWED_ROLES, ALLOWED_FLOWS
from policy.policy_engine import PolicyEngine
from utils.auth_client import AuthClient
from utils.openflow import FlowManager
from hosts.host_registry import HOSTS
from sessions.sessions import SessionManager
from api.api import PolicyAPIController

#------------------------------
# --- Zero Trust Controller ---
#------------------------------

class ZeroTrustController(app_manager.RyuApp):
    # Use OpenFlow 1.3 (required for modern SDN features)
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { "wsgi": WSGIApplication }

    def __init__(self, *args, **kwargs):
        """ Startup controller configuration

            Setup:
                policy level
                policy
                datastructures
                rest api

            Configures services:
                Auth client
                Flow manager
                Policy engine
                Session manager
        """
        super(ZeroTrustController, self).__init__(*args, **kwargs)

        self.policy_level = int(os.getenv("ZT_POLICY_LEVEL", "0"))
        self.logger.info("Policy level set to %s", self.policy_level)
        self.policy = POLICIES[self.policy_level]
        self.mac_to_port = {}
        self.allowed_sessions = {}

        wsgi = kwargs["wsgi"]
        wsgi.register(PolicyAPIController, {"zt_controller": self})
        self.datapaths = {}

        self.hosts = HOSTS
        self.allowed_roles = ALLOWED_ROLES
        self.allowed_flows = ALLOWED_FLOWS

        self.auth_client = AuthClient(self.logger)

        self.flow_manager = FlowManager(
            logger=self.logger,
            policy_getter=lambda: self.policy
        )

        self.policy_engine = PolicyEngine(
            policy_level=self.policy_level,
            policy=self.policy,
            hosts=self.hosts,
            allowed_roles=self.allowed_roles,
            allowed_flows=self.allowed_flows,
            auth_client=self.auth_client,
            logger=self.logger
        )

        self.session_manager = SessionManager(
            hosts=self.hosts,
            logger=self.logger,
            auth_callback=self.auth_client.is_authenticated,
            policy_callback=self.policy_engine.is_allowed_by_policy
        )

    #Run on new OpenFlow SwitchFeatures event when state=CONFIG_DISPATCHER
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """ Installs default rule when switch connects
                All unknown traffic to controller

            Args:
                ev (ryu event): reference
        """
        datapath = ev.msg.datapath
        self.flow_manager.datapaths[datapath.id] = datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.flow_manager.add_flow(datapath, 0, match, actions)

        self.logger.info("Switch connected: dpid=%s", datapath.id)

    # --- Learn MAC function ---
    def learn_mac(self, datapath, eth, in_port):
        """ Learns mac when packet arrives
                Prevents constant flooding after learning

            Args:
                datapath (ryu object): OpenFlow connection
                eth (object): parsed ethernet frame
                in_port (int): packet in port

            Returns output switch port or flood if destination unknown
        """
        dpid = datapath.id
        ofproto = datapath.ofproto

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        return self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

    # Run on new OpenFlow PacketIn event when state=MAIN_DISPATCHER
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """ Runs every time an unknown packet arrives

            Args:
                ev (ryu event): reference
        """
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]

        # Cleanup sessions
        self.session_manager.cleanup(self.policy)

        # Parse the incoming packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets (used internally by switches)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        out_port = self.learn_mac(datapath, eth, in_port)

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # ARP handling
        if arp_pkt:
            return self.flow_manager.forward_packet(datapath, msg, in_port, out_port)

        # ICMP handling
        if ip_pkt and icmp_pkt:
            return self.handle_icmp(datapath, msg, in_port, out_port, eth, ip_pkt, icmp_pkt)

        # TCP handling
        if ip_pkt and tcp_pkt:
            return self.handle_tcp(datapath, msg, in_port, out_port, eth, ip_pkt, tcp_pkt)

    def handle_icmp(self, datapath, msg, in_port, out_port, eth, ip_pkt, icmp_pkt):
        """ Handles icmp packets
                Echo requests are policy validated before
                temporary ICMP session are created.
                Echo replies are only allowed as verified
                return traffic.
            Args:
                datapath (ryu object): OpenFlow connection
                msg (ryu message): OpenFlow icmp event message
                in_port (int): packet in port
                out_port (int): packet out port
                eth (object): parsed ethernet frame
                ip_pkt (object): parsed ipv4 packet
                icmp_pkt (object): parsed icmp packet

        """
        parser = datapath.ofproto_parser

        src = ip_pkt.src
        dst = ip_pkt.dst
        icmp_type = icmp_pkt.type

        if icmp_type == 8:  # Echo request
            allowed = self.policy_engine.is_allowed_by_policy(
                src, dst, proto="icmp"
            )

            if allowed:
                self.session_manager.add_session(
                    src, dst,
                    proto="icmp",
                    policy_level=self.policy_level
                )
                self.logger.info("CREATE ICMP SESSION %s -> %s", src, dst)

        elif icmp_type == 0:  # Echo reply
            allowed = self.session_manager.is_return_traffic(
                src, dst,
                proto="icmp",
                policy=self.policy,
                icmp_type=icmp_type
            )

            if not allowed:
                allowed = self.policy_engine.is_allowed_by_policy(
                    dst, src, proto="icmp"
                )

            if allowed:
                self.logger.info("ALLOW ICMP RETURN %s -> %s", src, dst)
            else:
                self.logger.info("DROP ICMP RETURN %s -> %s", src, dst)

        else:
            allowed = False
            self.logger.info(
                "DROP ICMP %s -> %s type=%s (unsupported)",
                src, dst, icmp_type
            )

        match = self.flow_manager.icmp_match(parser, src, dst)

        if allowed:
            self.logger.info("ALLOW ICMP %s -> %s", src, dst)
            self.flow_manager.install_allow_flow(datapath, match, out_port)
            self.flow_manager.forward_packet(datapath, msg, in_port, out_port)
        else:
            self.logger.info("DROP ICMP %s -> %s", src, dst)
            self.flow_manager.drop_flow(datapath, match)

    def handle_tcp(self, datapath, msg, in_port, out_port, eth, ip_pkt, tcp_pkt):
        """ Handles tcp packets
                TCP flows are validated against policy,
                then converted into temporary verified
                sessions allowing controlled return traffic

            Args:
                self (object): reference
                datapath (ryu object): OpenFlow connection
                msg (ryu message): OpenFlow tcp event message
                in_port (int): packet in port
                out_port (int): packet out port
                eth (object): parsed ethernet frame
                ip_pkt (object): parsed ipv4 packet
                tcp_pkt (object): parsed tcp packet
        """
        parser = datapath.ofproto_parser

        src = ip_pkt.src
        dst = ip_pkt.dst
        src_port = tcp_pkt.src_port
        dst_port = tcp_pkt.dst_port
        is_syn = tcp_pkt.bits & tcp.TCP_SYN
        is_ack = tcp_pkt.bits & tcp.TCP_ACK

        # Check if session exists
        allowed = self.session_manager.get_existing_session(
            src, dst,
            proto="tcp",
            policy=self.policy,
            src_port=src_port,
            dst_port=dst_port
        )

        # Return traffic
        if not allowed:
            allowed = self.session_manager.is_return_traffic(
                src, dst,
                proto="tcp",
                policy=self.policy,
                src_port=src_port,
                dst_port=dst_port
            )

        # Check policy
        if not allowed:
            allowed = self.policy_engine.is_allowed_by_policy(
                src, dst,
                proto="tcp",
                dst_port=dst_port
            )

            # Start session
            if allowed and is_syn and not is_ack:
                self.session_manager.add_session(src, dst, "tcp", policy_level=self.policy_level, src_port=src_port, dst_port=dst_port)

        match = self.flow_manager.tcp_match(parser, src, dst, src_port, dst_port)

        # Allow
        if allowed:
            self.logger.info("ALLOW TCP %s -> %s:%s", src, dst, dst_port)
            self.flow_manager.install_allow_flow(datapath, match, out_port)
            self.flow_manager.forward_packet(datapath, msg, in_port, out_port)
        # Deny
        else:
            self.logger.info("DROP TCP %s -> %s:%s", src, dst, dst_port)
            self.flow_manager.drop_flow(datapath, match)

    # Set policy level function
    def set_policy_level(self, level):
        """ Sets policy level while running

            Args:
                level (int): policy level
        """
        if level not in POLICIES:
            return False, f"Invalid policy level: {level}"

        old_level = self.policy_level
        self.policy_level = level
        self.policy = POLICIES[level]
        self.policy_engine.policy_level = level
        self.policy_engine.policy = POLICIES[level]

        # Sessions from old policy are no longer trusted
        self.session_manager.clear()

        # Remove old installed flows
        self.flow_manager.clear_all_flows()

        self.logger.info(
            "POLICY LEVEL CHANGED old=%s new=%s",
            old_level,
            level
        )

        return True, f"Policy level changed from {old_level} to {level}"

    def update_allowed_role(self, src_role, dst_role, action):
        """ Updates allowed roles while running

            Args:
                src_role (string): source role
                dst_role (string): destination role
                action (string): allow/deny
        """
        pair = (src_role, dst_role)

        if action == "allow":
            self.allowed_roles.add(pair)
            message = f"Allowed role flow {src_role}->{dst_role}"

        elif action == "deny":
            self.allowed_roles.discard(pair)
            message = f"Denied role flow {src_role}->{dst_role}"

        else:
            return False, "Action must be 'allow' or 'deny'"

        self.session_manager.clear()
        self.flow_manager.clear_all_flows()

        self.logger.info("UPDATED ROLE POLICY %s", message)

        return True, message

    # --- Update allowed flow function ---
    def update_allowed_flow(self, src_ip, dst_ip, dst_port, action):
        """ Updates allowed flow while running

            Args:
                src_ip (string): source ip
                dst_ip (string): destination ip
                dst_port (int): destination port
                action (string): allow/deny
        """
        flow = (src_ip, dst_ip, int(dst_port))

        if action == "allow":
            self.allowed_flows.add(flow)
            message = f"Allowed flow {src_ip}->{dst_ip}:{dst_port}"

        elif action == "deny":
            self.allowed_flows.discard(flow)
            message = f"Denied flow {src_ip}->{dst_ip}:{dst_port}"

        else:
            return False, "Action must be 'allow' or 'deny'"

        self.session_manager.clear()
        self.flow_manager.clear_all_flows()

        self.logger.info("UPDATED MICROSEGMENTATION POLICY %s", message)

        return True, message
