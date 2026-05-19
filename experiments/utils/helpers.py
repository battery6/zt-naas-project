import os
import subprocess
import json
import csv
import math

#############################################
#      HELPER FUNCTIONS                     #
#          policy evaluation                #
#          API calls                        #
#          output to csv                    #
#############################################
def evaluate_policy(test, level, result):
    """ Evaluate policy function
            Determines if a policy is correctly applied or not

        Args:
            test (string): reference test
            level (int): policy level
            result (string): test result
    """
    expected = test.get("expected_by_level", {}).get(level, test.get("expected"))

    policy_correct = (
        (expected == "allow" and result == "allowed") or
        (expected == "deny" and result == "blocked")
    )

    return expected, policy_correct

def change_policy_level(level):
    """ Change policy level function
            Call API to change the current policy level

        Args:
            level (int): policy level after change
    """
    subprocess.run([
        "curl", "-X", "POST",
        f"http://127.0.0.1:8080/policy/level/{level}"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def authenticate_entity(name):
    """ Authenticate entity function
            Call API to authenticate entity on network

        Args:
            name (string): entity name
    """
    subprocess.run([
        "curl", "-k", "-X", "POST", "https://127.0.0.1:5000/login",
        "-H", "Content-Type: application/json",
        "-d", f'{{"username":"{name}","password":"pass123"}}'
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def update_attribute(ip, data):
    """ Update attribute function
            Call API to update attribute for entity on network

        Args:
            ip (string): ip of entity
            data (json): attribute data
    """

    result = subprocess.run([
        "curl", "-s", "-X", "POST",
        f"http://127.0.0.1:8080/hosts/{ip}/attributes",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(data)
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def update_flow(src, dst, port, action):
    """ Update flow function
            Call API to update flow policy

        Args:
            src (string): source ip
            dst (string): dst ip
            port (int): flow port
            action (string): allow/deny
    """

    result = subprocess.run([
        "curl", "-X", "POST",
        "http://127.0.0.1:8080/policy/flows",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": port,
            "action": action
        })
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def reset_controller_state():
    """ Reset controller state function
            Calls API to reset controller state
    """

    result = subprocess.run([
        "curl", "-X", "POST",
        "http://127.0.0.1:8080/reset"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Define fields for summary output functions
SUMMARY_FIELDS = {
    "architecture": [
        "level",
        "test_name",
        "src",
        "dst",
        "traffic_type",
        "legitimate",
        "expected",
        "protocol",
        "port",
        "result",
        "policy_correct",
    ],

    "ports": [
        "level",
        "test_name",
        "src",
        "dst",
        "traffic_type",
        "legitimate",
        "expected",
        "protocol",
        "port",
        "result",
        "policy_correct",
    ],

    "performance": [
        "level",
        "test_name",
        "iteration",
        "runs",
        "src",
        "dst",
        "traffic_type",
        "legitimate",
        "expected",
        "protocol",
        "port",
        "duration_ms",
        "transmitted",
        "received",
        "packet_loss_percent",
        "avg_rtt_ms",
        "result",
        "policy_correct",
    ],

    "dynamic": [
        "level",
        "test_name",
        "src",
        "dst",
        "traffic_type",
        "protocol",
        "port",
        "before_result",
        "after_result",
        "behavior_changed",
        "policy_correct",
        "policy_change_time_ms",
    ],

    "isolation": [
        "level",
        "test_name",
        "src",
        "dst",
        "traffic_type",
        "legitimate",
        "expected",
        "protocol",
        "port",
        "result",
        "policy_correct",
    ],

    "attack": [
        "level",
        "test_name",
        "src",
        "dst",
        "traffic_type",
        "legitimate",
        "expected",
        "protocol",
        "port",
        "result",
        "policy_correct",
    ],
}

def write_summary(rows, output_file, results_dir, experiment_name):
    """ Write summary function
            Write .csv summary of defined data

        Args:
            rows (list[dict]): test result rows
            output_file (string): filename
            results_dir (string): output directory
            experiment_name (string): name of experiment

    """
    os.makedirs(results_dir, exist_ok=True)
    summary_path = os.path.join(results_dir, output_file)

    fieldnames = SUMMARY_FIELDS[experiment_name]

    with open(summary_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames,
            extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)

def safe_div(numerator, denominator):
    """ safe_div function
            Fixes division by 0

        Args:
            numerator (float): numerator number
            denominator (float): denominator number
    """
    if denominator == 0:
        return None
    return numerator / denominator


def average(values):
    """ average function
            Calculates the average

        Args:
            values (list[float]): input numbers
    """
    values = [v for v in values if v is not None]
    if not values:
        return None
    return sum(values) / len(values)


def calculate_usability_metrics(level_rows):
    """ Calculate usability metrics

        Args:
            level_rows (list[dict]): result rows
    """
    legitimate_rows = [
        row for row in level_rows
        if row.get("legitimate") is True
    ]

    successful_legitimate = [
        row for row in legitimate_rows
        if row.get("result") == "allowed"
    ]

    blocked_legitimate = [
        row for row in legitimate_rows
        if row.get("result") == "blocked"
    ]

    durations = [
        float(row["duration_ms"])
        for row in successful_legitimate
        if row.get("duration_ms") not in [None, ""]
    ]

    avg_rtts = [
        float(row["avg_rtt_ms"])
        for row in successful_legitimate
        if row.get("avg_rtt_ms") not in [None, ""]
    ]

    return {
        "legitimate_success_rate": safe_div(
            len(successful_legitimate),
            len(legitimate_rows)
        ),

        "avg_legitimate_duration_ms": average(durations),
        "avg_legitimate_rtt_ms": average(avg_rtts),

        "blocked_legitimate_count": len(blocked_legitimate),
        "false_block_rate": safe_div(
            len(blocked_legitimate),
            len(legitimate_rows)
        ),
    }

def write_score_summary(rows, output_file, results_dir):
    """ Write score summary function
            Summary of legitimate/illegitimate successful/unsuccessful connections

        Args:
            rows (list[dict]): test result rows
            output_file (string): file name
            results_dir (string): output directory
    """

    os.makedirs(results_dir, exist_ok=True)
    summary_path = os.path.join(results_dir, output_file)

    levels = sorted(set(row["level"] for row in rows))

    fieldnames = [
        "level",
        "total_tests",
        "legitimate_tests",
        "illegitimate_tests",
        "allowed_legitimate",
        "blocked_legitimate",
        "allowed_illegitimate",
        "blocked_illegitimate",
        "security_score",
        "legitimate_success_rate",
        "avg_legitimate_duration_ms",
        "avg_legitimate_rtt_ms",
        "blocked_legitimate_count",
        "false_block_rate",
        "policy_accuracy",
    ]

    summary_rows = []

    for level in levels:
        level_rows = [row for row in rows if row["level"] == level]

        legitimate_rows = [
            row for row in level_rows
            if row.get("legitimate") is True
        ]

        illegitimate_rows = [
            row for row in level_rows
            if row.get("legitimate") is False
        ]

        allowed_legitimate = sum(
            1 for row in legitimate_rows
            if row["result"] == "allowed"
        )

        blocked_legitimate = sum(
            1 for row in legitimate_rows
            if row["result"] == "blocked"
        )

        allowed_illegitimate = sum(
            1 for row in illegitimate_rows
            if row["result"] == "allowed"
        )

        blocked_illegitimate = sum(
            1 for row in illegitimate_rows
            if row["result"] == "blocked"
        )

        security_score = (
            blocked_illegitimate / len(illegitimate_rows)
            if illegitimate_rows else None
        )

        usability = calculate_usability_metrics(level_rows)

        policy_accuracy = (
            sum(1 for row in level_rows if row["policy_correct"]) / len(level_rows)
            if level_rows else None
        )

        summary_rows.append({
            "level": level,
            "total_tests": len(level_rows),
            "legitimate_tests": len(legitimate_rows),
            "illegitimate_tests": len(illegitimate_rows),
            "allowed_legitimate": allowed_legitimate,
            "blocked_legitimate": blocked_legitimate,
            "allowed_illegitimate": allowed_illegitimate,
            "blocked_illegitimate": blocked_illegitimate,
            "security_score": security_score,
            "legitimate_success_rate": usability["legitimate_success_rate"],
            "avg_legitimate_duration_ms": usability["avg_legitimate_duration_ms"],
            "avg_legitimate_rtt_ms": usability["avg_legitimate_rtt_ms"],
            "blocked_legitimate_count": usability["blocked_legitimate_count"],
            "false_block_rate": usability["false_block_rate"],
            "policy_accuracy": policy_accuracy,
        })

    with open(summary_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)

def std_dev(values):
    """ std_dev function
            Calculate standard deviation

        Args:
            values (list[float]): input values
    """
    values = [v for v in values if v is not None]
    if len(values) < 2:
        return None

    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def write_performance_summary(rows, output_file, results_dir):
    """ Write performance summary function
            Write summary of performance metrics

        Args:
            rows (list[dict]): test result rows
            output_file (string): file name
            results_dir (string): output directory
    """

    os.makedirs(results_dir, exist_ok=True)
    summary_path = os.path.join(results_dir, output_file)

    fieldnames = [
        "level",
        "test_name",
        "protocol",
        "port",
        "runs",
        "successful_runs",
        "policy_correct_runs",
        "avg_duration_ms",
        "std_duration_ms",
        "avg_rtt_ms",
        "std_rtt_ms",
    ]

    groups = {}

    for row in rows:
        key = (
            row["level"],
            row["test_name"].rsplit("_run", 1)[0],
            row.get("protocol"),
            row.get("port"),
        )

        groups.setdefault(key, []).append(row)

    summary_rows = []

    for (level, test_name, protocol, port), group_rows in groups.items():
        durations = [
            float(row["duration_ms"])
            for row in group_rows
            if row.get("duration_ms") not in [None, ""]
            and row.get("result") == "allowed"
        ]

        rtts = [
            float(row["avg_rtt_ms"])
            for row in group_rows
            if row.get("avg_rtt_ms") not in [None, ""]
            and row.get("result") == "allowed"
        ]

        successful_runs = sum(
            1 for row in group_rows
            if row.get("result") == "allowed"
        )

        policy_correct_runs = sum(
            1 for row in group_rows
            if row.get("policy_correct") is True
        )

        summary_rows.append({
            "level": level,
            "test_name": test_name,
            "protocol": protocol,
            "port": port,
            "runs": len(group_rows),
            "successful_runs": successful_runs,
            "policy_correct_runs": policy_correct_runs,
            "avg_duration_ms": average(durations),
            "std_duration_ms": std_dev(durations),
            "avg_rtt_ms": average(rtts),
            "std_rtt_ms": std_dev(rtts),
        })

    with open(summary_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)
