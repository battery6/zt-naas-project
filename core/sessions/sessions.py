#######################################
#    Session Manager                  #
#        Handles sessions:            #
#            stores                   #
#            creates                  #
#            verifies                 #
#            checks return traffic    #
#            cleans                   #
#            clears                   #
#######################################

import time

class SessionManager:
    def __init__(self, hosts, logger, auth_callback, policy_callback):
        """ Initial configuration

            Args:
                hosts (dict): hosts
                logger (object): log
                auth_callback (function): authentication verification callback
                policy_callback (function): policy reevaluation callback
        """
        self.hosts = hosts
        self.logger = logger
        self.auth_callback = auth_callback
        self.policy_callback = policy_callback
        self.sessions = {}

    def add_session(self, src, dst, proto, policy_level, src_port=None, dst_port=None):
        """ Starts new session

           Args:
               src (string): source ip
               dst (string): destination ip
               proto (string): transmission protocol
               policy_level (int): policy level
               src_port (int): source port
               dst_port (int): destination port
        """

        src_info = self.hosts.get(src, {})
        dst_info = self.hosts.get(dst, {})

        key = (src, dst, proto, src_port, dst_port)
        now = time.time()

        self.sessions[key] = {
            "created_at": now,
            "last_seen": now,
            "last_verified": now,
            "src_role": src_info.get("role"),
            "dst_role": dst_info.get("role"),
            "policy_level": policy_level,
            "proto": proto,
            "src_port": src_port,
            "dst_port": dst_port
        }

        self.logger.info(
            "CREATE SESSION src=%s dst=%s proto=%s src_port=%s dst_port=%s",
            src, dst, proto, src_port, dst_port
        )

    def verify_session(self, key, session, src, dst, policy):
        """ Verify session is still valid

            Args:
                key (tuple): unique session identifier
                session (object): unique session
                src (string): source ip
                dst (string): destination ip
                policy (dict): policy configuration
        """

        now = time.time()

        max_age = policy.get("session_max_age", 0)
        reauth_interval = policy.get("session_reauth_interval", 0)

        if max_age > 0 and now - session["created_at"] > max_age:
            self.logger.info(
                "DROP REASON: session expired by max age src=%s dst=%s age=%.2fs",
                src, dst, now - session["created_at"]
            )
            del self.sessions[key]
            return False

        if policy["authentication"] and reauth_interval > 0:
            if now - session["last_verified"] > reauth_interval:
                if not self.auth_callback(src):
                    self.logger.info(
                        "DROP REASON: continuous verification failed src=%s dst=%s",
                        src, dst
                    )
                    del self.sessions[key]
                    return False
                if not self.policy_callback(src, dst, session["proto"], session["dst_port"]):
                    del self.sessions[key]
                    return False

                session["last_verified"] = now
                self.logger.info("REVERIFY SESSION OK src=%s dst=%s", src, dst)

        return True

    def get_existing_session(self, src, dst, proto, policy, src_port=None, dst_port=None):
        """ Checks if session exists

            Args:
                src (string): source ip
                dst (string): destination ip
                proto (string): transmission protocol
                src_port (int): source port
                dst_port (int): destination port
        """
        key = (src, dst, proto, src_port, dst_port)
        session = self.sessions.get(key)

        if not session:
            return False

        now = time.time()
        timeout = policy.get("session_idle_timeout", 0)

        if timeout > 0 and now - session["last_seen"] > timeout:
            self.logger.info("DROP REASON: session idle timeout src=%s dst=%s", src, dst)
            del self.sessions[key]
            return False

        if not self.verify_session(key, session, src, dst, policy):
            return False

        session["last_seen"] = now
        return True

    def is_return_traffic(self, src, dst, proto, policy, src_port=None, dst_port=None, icmp_type=None):
        """ Checks for return traffic

            Args:
                src (string): source ip
                dst (string): destination ip
                proto (string): transmission protocol
                policy (dict): policy configuration
                src_port (int): source port
                dst_port (int): destination port
                icmp_type (int): ICMP type (0 = echo reply)
        """
        if proto == "icmp":
            if icmp_type != 0:
                return False

            key = (dst, src, proto, dst_port, src_port)

        elif proto == "tcp":
            key = (dst, src, "tcp", dst_port, src_port)

        else:
            return False

        session = self.sessions.get(key)

        if not session:
            return False

        now = time.time()
        timeout = policy.get("session_idle_timeout", 0)

        orig_src, orig_dst, _, orig_src_port, orig_dst_port = key

        if timeout > 0 and now - session["last_seen"] > timeout:
            del self.sessions[key]
            return False

        if not self.verify_session(key, session, orig_src, orig_dst, policy):
            return False

        session["last_seen"] = now
        return True

    def cleanup(self, policy):
        """ Cleanup expired sessions

            Args:
                policy (dict): policy configuration
        """
        now = time.time()
        timeout = policy.get("session_idle_timeout", 0)

        if timeout == 0:
            return

        expired = []

        for key, session in self.sessions.items():
            if now - session["last_seen"] > timeout:
                expired.append(key)

        for key in expired:
            del self.sessions[key]

    def clear(self):
        """ Clear all sessions
        """
        self.sessions.clear()
