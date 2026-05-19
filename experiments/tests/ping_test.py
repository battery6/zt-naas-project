import os

from parsers.ping_parser import parse_ping
from utils.helpers import evaluate_policy

# --- Run Ping Test experiment ---
def run_ping_test(net, test, level, result_dir):
    """ Runs ping test
            Evaluates policy correctness

        Args:
            net (mininet net): test network
            test (dict): test configuration
            level (int): policy level
            result_dir: output directory

        Returns dict with result data
    """
    src = net.get(test["src"])
    dst = net.get(test["dst"])
    dst_ip = dst.IP()

    ping_count = test.get("count", 10)
    ping_timeout = test.get("timeout", 1)

    output = src.cmd(f"ping -c {ping_count} -W {ping_timeout} {dst_ip}")

    raw_path = os.path.join(result_dir, f"{test['name']}.txt")
    with open(raw_path, "w") as f:
        f.write(output)

    transmitted, received, packet_loss, avg_rtt, result = parse_ping(output)

    expected, policy_correct = evaluate_policy(test, level, result)

    return {
        "level": level,
        "test_name": test["name"],
        "src": test["src"],
        "dst": test["dst"],
        "traffic_type": test["traffic_type"],
        "legitimate": test.get("legitimate"),
        "expected": expected,
        "protocol": "icmp",
        "port": None,
        "duration_ms": None,
        "transmitted": transmitted,
        "received": received,
        "packet_loss_percent": packet_loss,
        "avg_rtt_ms": avg_rtt,
        "result": result,
        "policy_correct": policy_correct
    }
