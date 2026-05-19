import os
import time
import re

from utils.helpers import evaluate_policy

def run_http_test(net, test, level, result_dir):
    """ Runs HTTP test with curl, can handle https with cert
            Evaluates policy correctness

        Args:
            net (mininet net): test network
            test (dict): test configuration
            level (int): policy level
            result_dir (string): output directory

        Returns dict with result data
     """

    src = net.get(test["src"])
    dst = net.get(test["dst"])
    dst_ip = dst.IP()

    port = test.get("port", 80)
    protocol = test.get("protocol", "http")
    url = f"{protocol}://{dst_ip}:{port}"

    start = time.time()

    if protocol == "https":
        cmd = f"curl --cacert /tmp/ca.crt -m 5 -s -o /dev/null -w 'HTTP_CODE:%{{http_code}}\\n' {url}; echo EXIT_CODE:$?"
    else:
        cmd = f"curl -m 5 -s -o /dev/null -w 'HTTP_CODE:%{{http_code}}' {url}; echo EXIT_CODE:$?"

    output = src.cmd(cmd)

    duration_ms = (time.time() - start) * 1000

    raw_path = os.path.join(result_dir, f"{test['name']}.txt")
    with open(raw_path, "w") as f:
        f.write(output)

    http_match = re.search(r"HTTP_CODE:(\d+)", output)
    exit_match = re.search(r"EXIT_CODE:(\d+)", output)

    http_code = http_match.group(1) if http_match else "000"
    exit_code = int(exit_match.group(1)) if exit_match else None

    if exit_code == 0 and http_code.startswith(("2", "3")):
        result = "allowed"
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
        "protocol": protocol,
        "port": port,
        "duration_ms": duration_ms,
        "transmitted": None,
        "received": None,
        "packet_loss_percent": None,
        "avg_rtt_ms": None,
        "result": result,
        "policy_correct": policy_correct
    }
