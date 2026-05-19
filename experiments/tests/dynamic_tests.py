import time
from tests.http_test import run_http_test
from utils.helpers import update_attribute, update_flow, change_policy_level, reset_controller_state

def run_dynamic_abac_test(net, test, level, result_dir):
    """ Runs dynamic ABAC test

        Args:
            net (mininet net): test network
            test (dict): test configuration
            result_dir (string): output directory

        Returns dict of result data
    """

    if level != test["level"]:
        return None

    # Before
    update_attribute(test["attribute_ip"], test["before_attributes"])
    reset_controller_state()
    time.sleep(0.3)

    before_row = run_http_test(net, {
        "name": test["name"] + "_before",
        "src": test["src"],
        "dst": test["dst"],
        "protocol": test["protocol"],
        "port": test["port"],
        "traffic_type": test["traffic_type"],
        "expected": test["expected_before"],
    }, level, result_dir)

    # Change entity attributes
    start_change = time.time()

    update_attribute(test["attribute_ip"], test["after_attributes"])
    reset_controller_state()

    change_time_ms = (time.time() - start_change) * 1000
    time.sleep(0.3)

    # After
    after_row = run_http_test(net, {
        "name": test["name"] + "_after",
        "src": test["src"],
        "dst": test["dst"],
        "protocol": test["protocol"],
        "port": test["port"],
        "traffic_type": test["traffic_type"],
        "expected": test["expected_after"],
    }, level, result_dir)

    return {
        "level": level,
        "test_name": test["name"],
        "src": test["src"],
        "dst": test["dst"],
        "protocol": test["protocol"],
        "port": test["port"],
        "traffic_type": test["traffic_type"],
        "before_result": before_row["result"],
        "after_result": after_row["result"],
        "behavior_changed": before_row["result"] != after_row["result"],
        "policy_correct": (
            before_row["result"] == "allowed"
            and after_row["result"] == "blocked"
        ),
        "policy_change_time_ms": change_time_ms,
    }

def run_dynamic_flow_test(net, test, level, result_dir):
    """ Runs dynamic microsegmentation test

        Args:
            net (mininet net): test network
            test (dict): test configuration
            result_dir (string): output directory

        Returns dict of result data
    """

    if level != test["level"]:
        return None

    # Before
    reset_controller_state()
    time.sleep(0.3)

    before_row = run_http_test(net, {
        "name": test["name"] + "_before",
        "src": test["src"],
        "dst": test["dst"],
        "protocol": test["protocol"],
        "port": test["port"],
        "traffic_type": test["traffic_type"],
        "expected": test["expected_before"],
    }, level, result_dir)

    # Change flow policy
    start_change = time.time()

    update_flow(
        test["flow_src_ip"],
        test["flow_dst_ip"],
        test["flow_dst_port"],
        test["action"]
    )
    reset_controller_state()

    change_time_ms = (time.time() - start_change) * 1000
    time.sleep(0.3)

    # After
    after_row = run_http_test(net, {
        "name": test["name"] + "_after",
        "src": test["src"],
        "dst": test["dst"],
        "protocol": test["protocol"],
        "port": test["port"],
        "traffic_type": test["traffic_type"],
        "expected": test["expected_after"],
    }, level, result_dir)

    return {
        "level": level,
        "test_name": test["name"],
        "src": test["src"],
        "dst": test["dst"],
        "protocol": test["protocol"],
        "port": test["port"],
        "traffic_type": test["traffic_type"],
        "before_result": before_row["result"],
        "after_result": after_row["result"],
        "behavior_changed": before_row["result"] != after_row["result"],
        "policy_correct": (
            before_row["result"] == "allowed"
            and after_row["result"] == "blocked"
        ),
        "policy_change_time_ms": change_time_ms,
    }

def run_dynamic_level_test(net, test, level, result_dir):
    """ Runs dynamic policy level change test

        Args:
            net (mininet net): test network
            test (dict): test configuration
            level (int): policy level
            result_dir: output directory

       Returns dict of result data
    """

    if level != test["level"]:
        return None

    reset_controller_state()
    time.sleep(0.3)

    # Before
    before_row = run_http_test(net, {
        "name": test["name"] + "_before",
        "src": test["src"],
        "dst": test["dst"],
        "protocol": test["protocol"],
        "port": test["port"],
        "traffic_type": test["traffic_type"],
        "expected": test["expected_before"],
    }, level, result_dir)

    # Change policy level
    start_change = time.time()

    change_policy_level(test["new_level"])
    reset_controller_state()

    change_time_ms = (time.time() - start_change) * 1000
    time.sleep(0.3)

    # After
    after_row = run_http_test(net, {
        "name": test["name"] + "_after",
        "src": test["src"],
        "dst": test["dst"],
        "protocol": test["protocol"],
        "port": test["port"],
        "traffic_type": test["traffic_type"],
        "expected": test["expected_after"],
    }, test["new_level"], result_dir)

    return {
        "level": level,
        "new_level": test["new_level"],
        "test_name": test["name"],
        "src": test["src"],
        "dst": test["dst"],
        "protocol": test["protocol"],
        "port": test["port"],
        "traffic_type": test["traffic_type"],
        "before_result": before_row["result"],
        "after_result": after_row["result"],
        "behavior_changed": before_row["result"] != after_row["result"],
        "policy_correct": (
            before_row["result"] == "allowed"
            and after_row["result"] == "blocked"
        ),
        "policy_change_time_ms": change_time_ms,
    }
