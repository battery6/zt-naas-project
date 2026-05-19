import os
import time
from tests.tcp_test import run_tcp_test
from utils.helpers import evaluate_policy

def run_direct_attack_test(net, test, level, result_dir):
    """ Runs direct tcp attack

        Args:
            net (mininet network): test network
            test (dict): test configuration
            level (int): policy level
            result_dir (string): output directory
    """
    return run_tcp_test(net, test, level, result_dir)


def run_ip_spoof_attack_test(net, test, level, result_dir):
    """ Runs ip spoof attack
            Changes ip directly to simulate attack
                Evaluates policy correctness

        Args:
            net (mininet network): test network
            test (dict): test configuration
            level (int): policy level
            result_dir (string): output directory

        Returns dict of result data
    """
    attacker = net.get(test["src"])
    dst = net.get(test["dst"])
    dst_ip = dst.IP()

    spoof_ip = test["spoof_ip"]
    port = test["port"]

    original_ip = attacker.IP()
    intf = attacker.defaultIntf()

    raw_path = os.path.join(result_dir, f"{test['name']}.txt")

    # Save original config
    attacker.cmd(f"ip addr flush dev {intf}")
    attacker.cmd(f"ip addr add {spoof_ip}/24 dev {intf}")
    attacker.cmd(f"ip route add default via 10.0.4.1 || true")

    time.sleep(0.2)

    start = time.time()
    output = attacker.cmd(
        f"timeout 5 nc -zv {dst_ip} {port} 2>&1; echo EXIT_CODE:$?"
    )
    duration_ms = (time.time() - start) * 1000

    # Restore original config
    attacker.cmd(f"ip addr flush dev {intf}")
    attacker.cmd(f"ip addr add {original_ip}/24 dev {intf}")
    attacker.cmd(f"ip route add default via 10.0.4.1 || true")

    with open(raw_path, "w") as f:
        f.write(output)

    if "EXIT_CODE:0" in output:
        result = "allowed"
    elif "Connection refused" in output:
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
        "protocol": test["protocol"],
        "port": port,
        "duration_ms": duration_ms,
        "transmitted": None,
        "received": None,
        "packet_loss_percent": None,
        "avg_rtt_ms": None,
        "result": result,
        "policy_correct": policy_correct,
        "spoof_ip": spoof_ip,
    }
