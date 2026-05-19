"""

experiments.py
Runs experiments in Mininet topologi and outputs data as .csv file + logs
Author: Philip Hellzén

"""

import sys
import os
import re
import csv
import subprocess
import time
import argparse

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPERIMENTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, EXPERIMENTS_DIR)

from topology.main_topo import ZT_NaaS_Topo, configure_network, wait_for_servers
from parsers.controller_log_parser import parse_controller_log
from utils.helpers import (
    change_policy_level,
    authenticate_entity,
    update_attribute,
    update_flow,
    reset_controller_state,
    write_summary,
    write_score_summary,
    write_performance_summary
)

from tests.test_definitions import (
    ARCHITECTURE_TESTS,
    PORT_POLICY_TESTS,
    PERFORMANCE_TESTS,
    DYNAMIC_TESTS,
    ISOLATION_TESTS,
    ATTACK_TESTS
)
from tests.ping_test import run_ping_test
from tests.tcp_test import run_tcp_test
from tests.http_test import run_http_test
from tests.dynamic_tests import run_dynamic_abac_test, run_dynamic_flow_test, run_dynamic_level_test
from tests.attack_tests import run_direct_attack_test, run_ip_spoof_attack_test

RESULTS_DIR = os.path.join(BASE_DIR, "experiments", "results")

# Define tests
TEST_SETS = {
    "architecture": ARCHITECTURE_TESTS,
    "ports": PORT_POLICY_TESTS,
    "performance": PERFORMANCE_TESTS,
    "dynamic": DYNAMIC_TESTS,
    "isolation": ISOLATION_TESTS,
    "attack": ATTACK_TESTS,
}

def cleanup(net=None, controller=None, auth=None, controller_log=None, auth_log=None):
    """ Stops network, controller and all services

        Args:
            net (mininet net): network to be stopped
            controller (ryu controller): controller to be stopped
            auth (auth service): auth service to be stopped
            controller_log (string): controller log path
            auth_log (string): auth log path
    """
    if net:
        net.stop()

    if controller:
        controller.terminate()

    if auth:
        auth.terminate()

    if controller_log:
        controller_log.close()

    if auth_log:
        auth_log.close()

def start_controller(level, result_dir):
    """ Starts controller

        Args:
            level (int): level of policy
            result_dir (string): output directory
    """

    controller_log = open(os.path.join(result_dir, "controller.log"), "w")

    controller = subprocess.Popen(
        ["ryu-manager", os.path.join(BASE_DIR, "core", "zt_controller.py")],
        env={**os.environ, "ZT_POLICY_LEVEL": str(level)},
        stdout=controller_log,
        stderr=controller_log
    )

    time.sleep(3)
    return controller, controller_log

def start_auth_service(result_dir):
    """ Starts auth service

        Args:
            result_dir (string), output directory
    """

    auth_log = open(os.path.join(result_dir, "auth.log"), "w")

    auth = subprocess.Popen(
        ["python3", os.path.join(BASE_DIR, "services", "auth_service.py")],
        stdout=auth_log,
        stderr=auth_log
    )

    time.sleep(2)
    return auth, auth_log

def start_network():
    """ Start Mininet network
        with topology ZT_NaaS_Topo
    """

    net = Mininet(
        topo=ZT_NaaS_Topo(),
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
        autoSetMacs=True
    )

    net.start()
    configure_network(net)
    wait_for_servers(net)

    return net

def get_controller_metrics(result_dir):
    """ Output log file

        Args:
            result_dir (string): output directory
    """
    log_path = os.path.join(result_dir, "controller.log")
    return parse_controller_log(log_path)

def run_test(net, test, level, result_dir):
    """ Run test function
            Runs selected test on selected policy level

        Args:
            net (mininet network): network to run
            test (string): test to run
            level (int): policy level for test
            result_dir: output directory
    """
    runs = test.get("runs", 1)
    rows = []

    # Run several iterations depending on attributes
    for i in range (runs):
        protocol = test.get("protocol", "icmp")
        test_copy = dict(test)

        if runs > 1:
            test_copy["name"] = f"{test['name']}_run{i + 1}"

        if test.get("type") == "dynamic_abac":
            row = run_dynamic_abac_test(net, test_copy, level, result_dir)

        elif test.get("type") == "dynamic_flow":
            row = run_dynamic_flow_test(net, test_copy, level, result_dir)

        elif test.get("type") == "dynamic_level":
            row = run_dynamic_level_test(net, test_copy, level, result_dir)

        elif protocol == "icmp":
            row = run_ping_test(net, test_copy, level, result_dir)

        elif protocol == "tcp":
            row = run_tcp_test(net, test_copy, level, result_dir)

        elif protocol in ["http", "https"]:
            row = run_http_test(net, test_copy, level, result_dir)

        elif test.get("type") == "attack_direct":
            row = run_direct_attack_test(net, test_copy, level, result_dir)

        elif test.get("type") == "attack_ip_spoof":
            row = run_ip_spoof_attack_test(net, test_copy, level, result_dir)

        else:
            raise ValueError(f"Unknown protocol: {protocol}")

        if row:
            row["iteration"] = i+1
            row["runs"] = runs
            rows.append(row)

    if runs == 1:
        return rows[0] if rows else None

    return rows

# --- Run experiment at level function ---
def run_level(level, tests, experiment_dir):
    """ Run experiment function
            Runs experiment on the selected policy level with the selected test

        Args:
            level (int): level of policy for experiment
            tests (string): tests to run
            experiment_dir (string): output directory

    """
    result_dir = os.path.join(experiment_dir, f"level{level}")
    os.makedirs(result_dir, exist_ok=True)

    controller = auth = net = None
    controller_log = auth_log = None
    rows = []

    try:
        controller, controller_log = start_controller(level, result_dir)
        auth, auth_log = start_auth_service(result_dir)
        net = start_network()
        authenticate_entity("employee1")
        authenticate_entity("admin")
        authenticate_entity("employee2")

        for test in tests:
            reset_controller_state()
            time.sleep(0.5)
            result = run_test(net, test, level, result_dir)
            if isinstance(result, list):
                rows.extend(result)
            elif result:
                rows.append(result)

    finally:
        cleanup(net, controller, auth, controller_log, auth_log)

    metrics = get_controller_metrics(result_dir)

    for row in rows:
        row.update(metrics)

    return rows

def run_experiment(experiment_name):
    """ Run experiment function
            Runs the selected experiment

        Args:
            experiment_name (string): experiment to run
    """
    tests = TEST_SETS[experiment_name]


    experiment_dir = os.path.join(RESULTS_DIR, experiment_name)
    os.makedirs(experiment_dir, exist_ok=True)
    output_file = f"{experiment_name}.csv"

    if experiment_name == "dynamic":
        levels = sorted(set(test["level"] for test in tests))
    elif experiment_name == "architecture":
        levels = [1]
    else:
        levels = [0, 1, 2, 3, 4]

    all_rows = []

    # Run experiment for all levels
    for level in levels:
        print(f"Running {experiment_name} experiment on policy level {level}")
        rows = run_level(level, tests, experiment_dir)
        all_rows.extend(rows)

    # Write general summary
    write_summary(all_rows, output_file, experiment_dir, experiment_name)
    print(f"Summary written to: {experiment_dir}/{output_file}")

    # Write score summary
    write_score_summary(
        all_rows,
        f"{experiment_name}_scores.csv",
        experiment_dir
    )
    print(f"Score Summary written to: {experiment_dir}/{experiment_name}_scores.csv")

    # Write performance summary
    if experiment_name == "performance":
        write_performance_summary(all_rows, "performance_summary.csv", experiment_dir)
        print(f"Performance Summary written to: {experiment_dir}/performance_summary.csv")

##########################
#          MAIN          #
##########################
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--experiment",
        choices=["architecture", "ports", "performance", "dynamic", "isolation", "attack"],
        default="architecture"
    )

    args = parser.parse_args()

    setLogLevel("info")

    # Run experiment!
    run_experiment(args.experiment)
