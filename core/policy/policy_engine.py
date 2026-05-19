class PolicyEngine:
    def __init__(self, policy_level, policy, hosts, allowed_roles, allowed_flows, auth_client, logger):
        """ Configure engine

            Args:
                policy_level (int): policy level
                policy (dict): policy configuration
                hosts (dict) : hosts
                allowed_roles (set): allowed roles communication pairs
                allowed_flows (set): allowed flows microsegmentation flows
                auth_client (object): authentication and attribute service client
                logger (object): output log
        """
        self.policy_level = policy_level
        self.policy = policy
        self.hosts = hosts
        self.allowed_roles = allowed_roles
        self.allowed_flows = allowed_flows
        self.auth_client = auth_client
        self.logger = logger

    def is_allowed_by_attributes(self, src_info, dst_info, proto=None, dst_port=None):
        """ Checks if entity is allowed by entity attributes

            Args:
                src_info (dict): source data and attributes
                dst_info (dict): destination data and attributes
                proto (string): transmission protocol
                dst_port (int): destination port
        """
        src_role = src_info["role"]
        dst_role = dst_info["role"]

        device_trusted = src_info.get("device_trusted", False)
        mfa = src_info.get("mfa", False)
        risk = src_info.get("risk", "high")

        resource_sensitivity = dst_info.get("resource_sensitivity", "low")

        # All clients have to be trusted
        if src_role in ["user", "admin", "guest"]:
            if not device_trusted:
                self.logger.info("DROP REASON: untrusted device")
                return False

        # Admin -> DB requires MFA
        if src_role in ["user", "admin"] and dst_role == "db":
            if not mfa:
                self.logger.info("DROP REASON: MFA required for database")
                return False

        # High risk clients cant access sensitive resources
        if risk == "high" and resource_sensitivity in ["medium", "high"]:
            self.logger.info(
                "DROP REASON: high risk source cannot access sensitive resource"
            )
            return False

        # User cannot access DB directly
        if src_role == "user" and dst_role == "db":
            self.logger.info("DROP REASON: user cannot access database directly")
            return False

        return True

    def is_allowed_by_policy(self, src, dst, proto=None, dst_port=None):
        """ Checks if flow is allowed by policy

            Args:
                src (string): source ip
                dst (string): destination ip
                proto (string): transmission protocol
                dst_port (int): destination port 
        """
        policy = self.policy

        if policy["allow_all"]:
            return True

        src_info = self.hosts.get(src)
        dst_info = self.hosts.get(dst)

        self.logger.info(
            "POLICY CHECK level=%s src=%s dst=%s src_info=%s dst_info=%s",
            self.policy_level, src, dst, src_info, dst_info
        )

        if not src_info or not dst_info:
            return False

        src_segment = src_info["segment"]
        dst_segment = dst_info["segment"]
        src_role = src_info["role"]
        dst_role = dst_info["role"]

        ##############################################
        # Level 1 Segmentation                       #
        ##############################################

        # Segmentation
        if policy["segmentation"]:
            same_segment = src_segment == dst_segment

            allowed_segment_flow = (
                src_segment == "user" and dst_segment == "appserver"
            ) or (
                src_segment == "admin" and dst_segment == "appserver"
            ) or (
                src_segment == "admin" and dst_segment == "dbserver"
            ) or (
                src_segment == "appserver" and dst_segment == "user"
            ) or (
                src_segment == "appserver" and dst_segment == "admin"
            ) or (
                src_segment == "dbserver" and dst_segment == "admin"
            ) or (
                src_segment == "appserver" and dst_segment == "dbserver"
            ) or (
                src_segment == "dbserver" and dst_segment == "appserver"
            )

            if not same_segment and not allowed_segment_flow:
                self.logger.info("DROP REASON: segment violation (%s -> %s)", src_segment, dst_segment)
                return False


        ############################################
        # Level 2 Authentication and Authorization #
        ############################################

        # Authentication
        if policy["authentication"]:
            auth = self.auth_client.is_authenticated(src)
            if not auth:
                self.logger.info("DROP REASON: unauthenticated src=%s", src)
                return False

        # Authorization / RBAC
        if policy["role_authorization"]:
            if(src_role, dst_role) not in self.allowed_roles:
                self.logger.info("DROP REASON: unauthorized (%s -> %s)", src_role, dst_role)
                return False

        #################################################
        # Level 3 Attribute based access control        #
        #                                               #
        #################################################

        # Attribute based access / ABAC
        if policy["attribute_based_access"]:
            live_attributes = self.auth_client.get_live_attributes(src)

            src_info = {
                **src_info,
                **live_attributes
            }

            if not self.is_allowed_by_attributes(src_info, dst_info, proto, dst_port):
                self.logger.info(
                    "DROP REASON: ABAC denied src_info=%s dst_info=%s proto=%s port=%s",
                    src_info, dst_info, proto, dst_port
                )
                return False

        ##########################################
        # Level 4 Microsegmentation              #
        #          and ping disable              #
        ##########################################

        if policy["microsegmentation"]:
            if(src, dst, dst_port) not in self.allowed_flows:
                self.logger.info(
                    "DROP REASON: microsegmentation flow not allowed %s -> %s:%s",
                    src, dst, dst_port
                )
                return False

        if proto == "icmp" and policy["restrict_ping"]:
            self.logger.info("DROP REASON: ping disabled")
            return False

        return True


