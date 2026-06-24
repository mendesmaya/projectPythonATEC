import re

def is_valid_ipv4(ip_address: str) -> bool:
    """
    Validate the structure of an IPv4 address.

    Args:
        ip_address (str): The IP address to validate.

    Returns:
        bool: True if the IP address is valid, False otherwise.
    """
    octets: list[str] = ip_address.split(".")

    if len(octets) != 4:
        return False

    for octet in octets:
        if not octet.isdigit():
            return False

        number: int = int(octet)

        if number < 0 or number > 255:
            return False

    return True


def extract_log_event(raw_line: str) -> dict[str, str] | None:
    """
    Extract timestamp, source IP address and event description from a raw log line.

    Args:
        raw_line (str): Raw log line from the main file.

    Returns:
        dict[str, str] | None: Extracted event data, or None if the line is invalid.
    """
    pattern: str = (
        r"^\s*"
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
        r"\s*;\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3})"
        r"\s*;\s*"
        r"(.+?)"
        r"\s*$"
    )

    match_result: re.Match[str] | None = re.fullmatch(pattern, raw_line)

    if match_result is None:
        return None

    timestamp: str = match_result.group(1)
    source_ip: str = match_result.group(2)
    description: str = match_result.group(3)

    if not is_valid_ipv4(source_ip):
        return None

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "description": description
    }
