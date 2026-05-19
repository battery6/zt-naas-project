###############################################
#    Flow Manager                             #
#        Manages OpenFlow flows in switches   #
###############################################

class FlowManager:
    def __init__(self, logger, policy_getter):
        """ Initial configuration

            Args:
                logger (object): log
                policy_getter (function): returns current policy configuration
        """

        self.logger = logger
        self.policy_getter = policy_getter
        self.datapaths = {}

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """ Add flow to switch

            Args:
                datapath (ryu object): switch OpenFlow connection
                priority (int): flow priority
                match (object): OpenFlow match rule
                actions (list): actions applied to matching traffic
                idle_timeout (int): removed flow after inactivity
                hard_timeout (int): removed flow after fixed lifetime
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Define how packets should be processed
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        # Create the flow rule
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )

        datapath.send_msg(mod)

    def drop_flow(self, datapath, match):
        """ Install drop flow rule in switch

            Args:
                datapath (ryu object): switch OpenFlow connection
                match (object): OpenFlow match rule
        """
        self.add_flow(datapath, 100, match, [], idle_timeout=5)


    def install_allow_flow(self, datapath, match, out_port):
        """ Install allow flow rule in switch

            Args:
                datapath (ryu object): switch OpenFlow connection
                match (object): OpenFlow match rule
                out_port: flow out port
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if out_port == ofproto.OFPP_FLOOD:
            return

        actions = [parser.OFPActionOutput(out_port)]
        policy = self.policy_getter()
        idle_timeout = policy["idle_timeout"]
        hard_timeout = policy["hard_timeout"]

        self.add_flow(
            datapath=datapath,
            priority=100,
            match=match,
            actions=actions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )

    def clear_all_flows(self):
        """ Clears all flow rules from all connected switches
        """
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            match = parser.OFPMatch()

            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )

            datapath.send_msg(mod)

            # Reinstall table-miss rule
            actions = [parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )]

            self.add_flow(datapath, 0, parser.OFPMatch(), actions)

        self.logger.info("All flows cleared and table-miss rules reinstalled")

    # --- Forward packet function (arp) ---
    def forward_packet(self, datapath, msg, in_port, out_port):
       """ Forward one packet without installing flow rule
               Used for ARP

           Args:
               datapath (ryu object): switch OpenFlow connection
               msg (ryu message):
               in_port (int): incoming packet
               out_port (int): outgoing packet
       """

       parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )

        datapath.send_msg(out)

    # --- TCP match function ---
    def tcp_match(self, parser, src, dst, src_port, dst_port):
        """ Create OpenFlow rule match for TCP traffic

            Args:
                parser (ryu object): OpenFlow parser
                src (string): source IP address
                dst (string): destination IP address
                src_port (int): source TCP port
                dst_port (int): destination TCP port
        """
        return parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src,
            ipv4_dst=dst,
            ip_proto=6,
            tcp_src=src_port,
            tcp_dst=dst_port
        )

    # --- ICMP match function ---
    def icmp_match(self, parser, src, dst):
        """ Create OpenFlow rule match for ICMP traffic

            Args:
                parser (ryu object): OpenFlow parser
                src (string): source IP address
                dst (string): destination IP address
        """
        return parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src,
            ipv4_dst=dst,
            ip_proto=1
        )
