# ZT-NaaS Project — Zero-Trust Network-as-a-Service (prototype)

Short description
- This repository contains a bachelor-level prototype of a Zero-Trust Network-as-a-Service (ZT-NaaS) built on the Ryu OpenFlow controller and Mininet experiments. The controller enforces layered policy (segmentation, authentication, RBAC, ABAC and microsegmentation) and exposes a local REST API for runtime changes used by the experiment harness.

What is in this repo (high level)
- `core/` — controller implementation and API
  - `core/zt_controller.py` — Ryu application (packet-in handling, session creation, flow installation)
  - `core/api/api.py` — WSGI API registered with Ryu; mutating endpoints require localhost
- `core/policy/` — `policies.py` and `policy_engine.py` — policy definitions and evaluation
- `core/hosts/`, `core/sessions/` — canonical host definitions and runtime session manager
- `core/utils/` — `openflow.py` (FlowManager helpers), `auth_client.py` (talks to auth service)
- `services/` — small Flask-based services used in experiments (auth, http, https, ssh, db)
- `topology/` — Mininet topology and helpers (`main_topo.py`)
- `experiments/` — experiment orchestration and result parsing
- `tests/` — experiment tests used by the harness

Quick start (Linux / WSL)
1. Install dependencies required by Mininet and Ryu (Mininet+Ryu are Linux-centric — use Ubuntu or WSL2 with network privileges). See `DEVELOPER.md` for detailed install steps.
2. Start the authentication service (on the same host as the controller):
```bash
python3 services/auth_service.py
```
3. Start the controller (pick policy level):
```bash
ZT_POLICY_LEVEL=1 ryu-manager core/zt_controller.py
```
4. Run the experiments runner (starts Mininet, controller and auth service when used from experiments script):
```bash
python3 experiments/experiments.py --experiment architecture
```

Useful API examples
- Get current policy level:
```
curl http://127.0.0.1:8080/policy/level
```
- Set policy level (must come from localhost):
```
curl -X POST http://127.0.0.1:8080/policy/level/2
```
- Allow a microsegmentation flow (example):
```
curl -s -X POST http://127.0.0.1:8080/policy/flows \
  -H 'Content-Type: application/json' \
  -d '{"src_ip": "10.0.1.11", "dst_ip": "10.0.3.12", "dst_port": 5432, "action": "allow"}'
```

Where to look when editing
- Policy logic: `core/policy/policies.py` and `core/policy/policy_engine.py`
- Packet handling / flow install: `core/zt_controller.py` and `core/utils/openflow.py`
- Session lifecycle: `core/sessions/sessions.py`
- Auth integration: `services/auth_service.py` and `core/utils/auth_client.py`
- Experiments and topology: `experiments/` and `topology/main_topo.py`

Known issues & recommended fixes (short)
- Hardcoded absolute paths in `topology/main_topo.py` and `scripts/run_system.sh` — make paths repo-relative and configurable. Currently these lines reference `/home/philip/zt-naas-project/...` and `~/zt-naas-project`.
- `topology/main_topo.py` writes multiple services to the same log filename (e.g. `h4_app.log`) — use distinct per-service logs.
- Experiment helpers use `curl` via `subprocess` (platform-dependent) and swallow return codes — replace with Python `requests` calls and check responses.
- Process startup uses naive `time.sleep()` waits without verifying process health — improve by polling process state or checking startup log messages.
- No `requirements.txt` or developer guide; see `DEVELOPER.md` for environment setup and recommended `requirements.txt` contents.

If you plan to run the experiments for your thesis: follow `DEVELOPER.md` next (operator steps, required system packages, and troubleshooting tips).
