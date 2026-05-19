import os

def parse_controller_log(log_path):
    """ Parse controller log function
            Parses metrics from controller log

        Args:
            log_path (string): path to controller log
    """

    metrics = {
        "switches_connected": 0,
        "table_miss_installed": False,
        "policy_checks": 0,
        "allow_decisions": 0,
        "drop_decisions": 0,
        "sessions_created": 0,
        "sessions_verified": 0,
        "flows_cleared": 0,
    }

    if not os.path.exists(log_path):
        return metrics

    with open(log_path, "r") as f:
        lines = f.readlines()

    for line in lines:
        if "Switch connected: dpid=" in line:
            metrics["switches_connected"] += 1

        if "POLICY CHECK" in line:
            metrics["policy_checks"] += 1

        if "ALLOW " in line:
            metrics["allow_decisions"] += 1

        if "DROP " in line:
            metrics["drop_decisions"] += 1

        if "CREATE SESSION" in line:
            metrics["sessions_created"] += 1

        if "REVERIFY SESSION OK" in line:
            metrics["sessions_verified"] += 1

        if "All flows cleared" in line:
            metrics["flows_cleared"] += 1

    metrics["table_miss_installed"] = metrics["switches_connected"] > 0

    return metrics
