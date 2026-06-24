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
