import re

def parse_ping(output):
    """ Parse ping function
            Parses ping data

        Args:
            output (string): ping output

    """

    transmitted = received = packet_loss = None
    avg_rtt = None

    packet_match = re.search(
        r"(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss",
        output
    )

    if packet_match:
        transmitted = int(packet_match.group(1))
        received = int(packet_match.group(2))
        packet_loss = float(packet_match.group(3))

    rtt_match = re.search(
        r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms",
        output
    )

    if rtt_match:
        avg_rtt = float(rtt_match.group(1))

    result = "allowed" if received and received > 0 else "blocked"

    return transmitted, received, packet_loss, avg_rtt, result
