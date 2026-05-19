import json
import os
from webob import Response
from ryu.app.wsgi import ControllerBase, route


class PolicyAPIController(ControllerBase):

    def __init__(self, req, link, data, **config):
        """ Startup API controller configuration

            Setup:
                reference to Zero Trust controller
        """
        super(PolicyAPIController, self).__init__(req, link, data, **config)
        self.zt_controller = data["zt_controller"]

    def json_response(self, body, status=200):
        """ Creates json response

            Args:
                body (dict): response body
                status (int): http status code
        """
        return Response(
            status=status,
            content_type="application/json",
            body=json.dumps(body).encode("utf-8")
        )

    def read_json_body(self, req):
        """ Reads json body from request

            Args:
                req (request): http request

            Returns parsed json body or None on failure
        """
        try:
            if not req.body:
                return {}
            return json.loads(req.body.decode("utf-8"))
        except Exception:
            return None

    def require_localhost(self, req):
        """ Checks if request comes from localhost

            Args:
                req (request): http request

            Returns:
                bool: True if localhost
        """
        return req.remote_addr in ["127.0.0.1", "::1"]

    @route("policy", "/policy/level", methods=["GET"])
    def get_policy_level(self, req, **kwargs):
        """ Gets current policy level and policy

            Args:
                req (request): http request
                kwargs (dict): route arguments
        """
        body = {
            "policy_level": self.zt_controller.policy_level,
            "policy": self.zt_controller.policy,
        }

        return self.json_response(body)

    @route("policy", "/policy/level/{level}", methods=["POST"])
    def set_policy_level(self, req, **kwargs):
        """ Updates policy level while controller is running

            Args:
                req (request): http request
                kwargs (dict): route arguments
        """
        if not self.require_localhost(req):
            return self.json_response({"error": "Forbidden"}, status=403)

        try:
            level = int(kwargs["level"])
        except ValueError:
            return self.json_response(
                {"error": "Level must be an integer"},
                status=400
            )

        success, message = self.zt_controller.set_policy_level(level)

        return self.json_response({
            "success": success,
            "message": message,
            "policy_level": self.zt_controller.policy_level
        }, status=200 if success else 400)

    @route("policy", "/policy/roles", methods=["GET"])
    def get_allowed_roles(self, req, **kwargs):
        """ Gets allowed role communication pairs

            Args:
                req (request): http request
                kwargs (dict): route arguments
        """
        roles = [
            {"src_role": src, "dst_role": dst}
            for src, dst in sorted(self.zt_controller.allowed_roles)
        ]

        return self.json_response({
            "allowed_roles": roles
        })

    @route("policy", "/policy/roles", methods=["POST"])
    def set_allowed_role(self, req, **kwargs):
        """ Updates allowed role communication while running

            Args:
                req (request): http request
                kwargs (dict): route arguments
        """
        if not self.require_localhost(req):
            return self.json_response({"error": "Forbidden"}, status=403)

        data = self.read_json_body(req)

        if data is None:
            return self.json_response(
                {"error": "Invalid JSON body"},
                status=400
            )

        src_role = data.get("src_role")
        dst_role = data.get("dst_role")
        action = data.get("action")

        if not src_role or not dst_role or action not in ["allow", "deny"]:
            return self.json_response({
                "error": "Expected src_role, dst_role and action='allow' or 'deny'"
            }, status=400)

        success, message = self.zt_controller.update_allowed_role(
            src_role,
            dst_role,
            action
        )

        return self.json_response({
            "success": success,
            "message": message
        }, status=200 if success else 400)

    @route("policy", "/hosts/{ip}/attributes", methods=["GET"])
    def get_host_attributes(self, req, **kwargs):
        """ Gets host attributes

            Args:
                req (request): http request
                kwargs (dict): route arguments
        """
        ip = kwargs["ip"]

        if ip not in self.zt_controller.hosts:
            return self.json_response({
                "error": f"Unknown host: {ip}"
            }, status=404)

        base = self.zt_controller.hosts.get(ip, {})
        live = self.zt_controller.auth_client.get_live_attributes(ip)

        return self.json_response({
            "ip": ip,
            "base_attributes": base,
            "live_attributes": live,
            "effective_attributes": {
                **base,
                **live
            }
        })

    @route("policy", "/hosts/{ip}/attributes", methods=["POST"])
    def set_host_attributes(self, req, **kwargs):
        """ Updates host attributes while running

            Args:
                req (request): http request
                kwargs (dict): route arguments
        """
        if not self.require_localhost(req):
            return self.json_response({"error": "Forbidden"}, status=403)

        ip = kwargs.get("ip")
        data = self.read_json_body(req)

        if data is None:
            return self.json_response(
                {"error": "Invalid JSON body"},
                status=400
            )

        success, message, updated = (
            self.zt_controller.update_host_attributes(ip, data)
        )

        return self.json_response({
            "success": success,
            "message": message,
            "ip": ip,
            "attributes": updated
        }, status=200 if success else 400)

    @route("policy", "/policy/flows", methods=["GET"])
    def get_allowed_flows(self, req, **kwargs):
        """ Gets allowed microsegmentation flows

            Args:
                req (request): http request
                kwargs (dict): route arguments
        """
        flows = [
            {
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port
            }
            for src, dst, port in sorted(self.zt_controller.allowed_flows)
        ]

        return self.json_response({
            "allowed_flows": flows
        })

    @route("policy", "/policy/flows", methods=["POST"])
    def set_allowed_flow(self, req, **kwargs):
        """ Updates allowed microsegmentation flows while running

            Args:
                req (request): http request
                kwargs (dict): route arguments
        """
        if not self.require_localhost(req):
            return self.json_response({"error": "Forbidden"}, status=403)

        data = self.read_json_body(req)

        if data is None:
            return self.json_response(
                {"error": "Invalid JSON body"},
                status=400
            )

        src_ip = data.get("src_ip")
        dst_ip = data.get("dst_ip")
        dst_port = data.get("dst_port")
        action = data.get("action")

        if (
            not src_ip or
            not dst_ip or
            dst_port is None or
            action not in ["allow", "deny"]
        ):
            return self.json_response({
                "error": "Expected src_ip, dst_ip, dst_port and action='allow' or 'deny'"
            }, status=400)

        try:
            dst_port = int(dst_port)
        except ValueError:
            return self.json_response({
                "error": "dst_port must be an integer"
            }, status=400)

        success, message = self.zt_controller.update_allowed_flow(
            src_ip,
            dst_ip,
            dst_port,
            action
        )

        return self.json_response({
            "success": success,
            "message": message,
            "flow": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port
            }
        }, status=200 if success else 400)

    @route("policy", "/reset", methods=["POST"])
    def reset_state(self, req, **kwargs):
        """ Resets controller runtime state

            Clears:
                sessions
                installed flows

            Args:
                req (request): http request
                kwargs (dict): route arguments
        """
        self.zt_controller.session_manager.clear()
        self.zt_controller.flow_manager.clear_all_flows()

        return self.json_response({
            "success": True,
            "message": "Controller state reset (sessions + flows)"
        })
