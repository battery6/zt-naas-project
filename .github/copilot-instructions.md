## Quick orientation for AI coding agents

This repo implements a Zero-Trust Network-as-a-Service (ZT-NaaS) prototype built on the Ryu OpenFlow controller and Mininet experiments. The controller enforces policy (microsegmentation, ABAC-like attributes, and session-based return traffic) and exposes a local REST API for runtime changes.

Keep the guidance below short and concrete so you can be productive quickly.

### Big-picture architecture
- Core controller: `core/zt_controller.py` — Ryu app. Main responsibilities: packet-in handling, learning MACs, calling the PolicyEngine, creating/clearing sessions and installing OpenFlow rules via the FlowManager.
- REST API: `core/api/api.py` — WSGI controller registered into Ryu's WSGIApplication. API is intentionally restricted: mutating endpoints only accept requests from localhost.
- Policy: `policy/` — policy definitions and the `PolicyEngine` (policy maps such as `POLICIES`, `ALLOWED_ROLES`, `ALLOWED_FLOWS` are referenced from `zt_controller`).
- Hosts & sessions: `hosts/host_registry.py`, `sessions/sessions.py` — canonical host attributes and runtime session management used to allow return traffic.
- Utilities: `utils/` — contains `auth_client.py` (talks to the separate auth service), `openflow.py` (FlowManager helpers used to create matches, install/drop flows).
- Services: `services/` — small Flask apps used in experiments (auth_service, http/https apps). The `auth_service` exposes `/login`, `/authenticated`, and `/attributes/<ip>` which the controller queries via `AuthClient`.
- Experiments/topology: `topology/main_topo.py`, `experiments/experiments.py` — glue to run Mininet, start the controller and services, and execute tests under different policy levels.

### Important runtime facts (how to run & debug)
- Controller is started with ryu-manager: set `ZT_POLICY_LEVEL` in the env to pick a policy (e.g. `ZT_POLICY_LEVEL=1 ryu-manager core/zt_controller.py`). The controller reads `ZT_POLICY_LEVEL` at startup.
- Auth service: `services/auth_service.py` — start with `python3 services/auth_service.py`. It listens on port 5000 by default.
- Experiments orchestrator: `experiments/experiments.py` — runs Mininet, controller and auth service and drives test scenarios. Use `python3 experiments/experiments.py --experiment architecture` (other experiment names: `ports`, `performance`, `dynamic`, `isolation`, `attack`).
- Script: `scripts/run_system.sh` is a convenience but assumes a Linux path layout (home dir `~/zt-naas-project`). Experiments and Mininet require a Linux environment (or WSL with network privileges).
- Logs: experiments write controller logs to `experiments/results/.../controller.log`; the helper scripts in `scripts/` send logs to `~/zt-naas-project/logs/controller.log` and `auth.log`.

Notes about environment: Mininet + Ryu are Linux-centric. If you're editing code on Windows, tests/experiments must run on a Linux host/VM or WSL with the necessary privileges.

### Project-specific conventions & gotchas
- Local-only API: mutating endpoints (policy changes, host attributes, flow allow/deny, reset) check `PolicyAPIController.require_localhost` — calls must come from 127.0.0.1 or ::1. When writing integration code or tests, call the API from the machine running the controller.
- Policy change flow: when policy or allowed-roles/flows are changed, the controller clears sessions and calls `flow_manager.clear_all_flows()` so tests expect a cold state after updates (see `set_policy_level`, `update_allowed_role`, `update_allowed_flow` in `core/zt_controller.py`).
- Session lifecycle: TCP sessions are created on SYN (if allowed by policy) and used to allow return traffic; ICMP echo request triggers temporary ICMP sessions. Search for `session_manager.add_session` and `is_return_traffic` use sites.
- FlowManager API (from `utils/openflow.py`): controller uses helpers such as `tcp_match`, `icmp_match`, `install_allow_flow`, `drop_flow`, `forward_packet`. When modifying OpenFlow behavior, prefer using these helpers to preserve existing flow installation and packet forwarding semantics.
- Auth integration: `AuthClient` is the single source for live attributes and authentication checks — it queries the auth service endpoints. Tests and experiments assume predictable sample users in `services/auth_service.py` (see `USERS`, `authenticated_hosts`, and `attributes` dictionaries).

### Examples you can use directly
- Start controller with policy level 2 (linux/WSL):
```bash
ZT_POLICY_LEVEL=2 ryu-manager core/zt_controller.py
```

- Start auth service (in same host):
```bash
python3 services/auth_service.py
```

- Change policy level via local API (controller must be running on the same host):
```bash
curl -X POST http://127.0.0.1:8080/policy/level/1
```
(The WSGI port is the one Ryu binds for the app; in most experiments the controller exposes the WSGI API on the default Ryu WSGI port.)

- Allow a microsegmentation flow via API (example JSON body):
```bash
curl -s -X POST http://127.0.0.1:8080/policy/flows \ 
  -H 'Content-Type: application/json' \ 
  -d '{"src_ip": "10.0.1.11", "dst_ip": "10.0.3.12", "dst_port": 3306, "action": "allow"}'
```

### Where to look when editing
- Policy logic: `policy/` (POLICIES and PolicyEngine). Policy definitions drive `zt_controller` decisions — any change here alters allowed sessions dramatically.
- Packet handling: `core/zt_controller.py` — the quickest way to understand packet flows and where policy checks occur.
- Flow primitives: `utils/openflow.py` — change match/installation behavior here to affect all flow rules.
- Host attributes & auth: `hosts/host_registry.py` and `services/auth_service.py` + `utils/auth_client.py`.
- Experiments and tests: `experiments/experiments.py`, `tests/*` and `topology/main_topo.py` — useful examples for integration-level changes.

### Quick-edit patterns for PRs
- If you modify policy behavior, update or add a small experiment/test under `experiments/` or `tests/` that exercises the new path and add expected output to `experiments/results` for manual validation.
- Preserve API guard: do not remove the localhost checks in `PolicyAPIController.require_localhost` unless you add authentication — tests and experiment flows assume local-only control.

If anything above is unclear or you want more detail about a specific area (policy internals, FlowManager helpers, or the experiments/test harness), tell me which area and I will expand this file with small targeted examples or add helper snippets/tests.
