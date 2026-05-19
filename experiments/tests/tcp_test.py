import os
import re
import time

from parsers.ping_parser import parse_ping
from utils.helpers import evaluate_policy

# --- Run TCP test function ---
def run_tcp_test(net, test, level, result_dir):
    """ Run tcp test with netcat
            Evaluates policy correctness

        Args:
            net (mininet net): test network
            test (dict): test configuration
            level (int): policy level
            result_dir: output directory

        Returns dict of result data
    """

    src = net.get(test["src"])
    dst = net.get(test["dst"]) 
    dst_ip = dst.IP()
    port = test["port"]

    start = time.time()
    output = src.cmd(f"timeout 5 nc -zv {dst_ip} {port} 2>&1; echo EXIT_CODE:$?")
    duration_ms = (time.time() - start) * 1000

    raw_path = os.path.join(result_dir, f"{test['name']}.txt")
    with open(raw_path, "w") as f:
        f.write(output)

    exit_match = re.search(r"EXIT_CODE:(\d+)", output)
    exit_code = int(exit_match.group(1)) if exit_match else None

    if exit_code == 0:
        result = "allowed"
    elif exit_code == 1 and "Connection refused" in output:
        result = "allowed"
    elif exit_code == 124:
        result = "blocked"
    else:
        result = "blocked"

    expected, policy_correct = evaluate_policy(test, level, result)

    return {
        "level": level,
        "test_name": test["name"],
        "src": test["src"],
        "dst": test["dst"],
        "traffic_type": test["traffic_type"],
        "legitimate": test.get("legitimate"),
        "expected": expected,
        "protocol": "tcp",
        "port": port,
        "duration_ms": duration_ms,
        "transmitted": None,
        "received": None,
        "packet_loss_percent": None,
        "avg_rtt_ms": None,
        "result": result,
        "policy_correct": policy_correct
    }
