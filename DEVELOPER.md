# Developer / Experimenter guide

This file expands on how to set up a development environment, run experiments, and covers common pitfalls.

1) Platform and prerequisites
- Mininet and Ryu are Linux-native. Use Ubuntu 20.04/22.04 or a Linux VM. WSL2 may work if network privileges are granted but many network experiments require sudo and kernel features.
- System packages (Ubuntu example):
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git build-essential libssl-dev
# Mininet + Open vSwitch + other deps - follow Mininet install docs
sudo apt install -y mininet openvswitch-switch
```

2) Python environment
- Create and activate a virtualenv:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install flask requests ryu
```
- Note: `mininet` is typically installed via apt or from source; don't rely on pip for mininet core.

3) Recommended repo files to add (I can add these for you):
- `requirements.txt` suggestion (add to repo):
```
flask
requests
ryu
# mininet is not pip-installable in many environments — install via system package or source
```

4) Running locally — simple flow
- Start auth service (must be visible to controller on 127.0.0.1:5000):
```bash
python3 services/auth_service.py
```
- Start controller (example sets policy level via environment):
```bash
ZT_POLICY_LEVEL=2 ryu-manager core/zt_controller.py
```
- If you want to run the experiments harness (it starts controller/auth and Mininet when invoked from the orchestrator):
```bash
python3 experiments/experiments.py --experiment architecture
```

5) WSL notes (if using Windows host)
- WSL2 networking and running Mininet/ryu inside WSL may require elevated privileges. Use a full Linux VM if experiments access raw sockets or require kernel modules.

6) Known code issues and recommended code changes (details & patches recommended)
- Replace absolute paths in `topology/main_topo.py` (service launches and certificate copy) with a repo-root-based `BASE_DIR` variable. This will make topology portable across machines.
- In `topology/main_topo.py`, create `logs/` directory under repo root and write per-service log files (`h5_app_http.log`, `h5_app_https.log`, `h5_app_ssh.log`, `h6_db.log` etc.).
- Convert `experiments/utils/helpers.py` API calls from `curl` subprocess to `requests` with timeouts and response checks. This prevents silent failures and improves portability.
- Enhance `experiments/experiments.py` process startup functions to poll `controller.poll()` and `auth.poll()` or inspect the created log for a known success pattern, and fail early if the process crashes.
- Add unit tests (pytest) for `core/policy/policy_engine.py` and `core/sessions/sessions.py` covering key policy levels and session lifecycle behaviors.

7) Suggested small checklist before running full experiments
- Ensure `logs/` folder exists and is writable by the user running Mininet and the controller.
- Confirm `ryu-manager` is installed and in PATH.
- Ensure no other process is binding ports 6653 (OpenFlow), 8080 (WSGI), or 5000 (auth service).

8) Troubleshooting tips
- Controller not connecting to switches: check that Mininet remote controller is configured to 127.0.0.1:6653 and that the controller is listening; look in `experiments/results/.../controller.log`.
- Auth service returning empty attributes: verify `services/auth_service.py` is running and that `AuthClient` can reach `https://127.0.0.1:5000` (note: `AuthClient` sets `verify=False` to ignore TLS in experiments).
- Logs missing or empty: check the absolute path usage in `topology/main_topo.py` and create repo-local `logs/` directory.

If you want, I can apply the high-priority code changes now (make topology paths repo-relative, create distinct log names, and convert experiment helper curl calls to `requests`). Say "Do Plan A" and I'll implement the edits and run quick checks.
