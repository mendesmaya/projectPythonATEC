from typing import Optional
from parser import is_valid_ipv4

class LogEvent:
    """
    Base class that represents a security event extracted from a log.

    ENCAPSULATION:
        All attributes are PRIVATE (__ prefix) to prevent direct external 
        access. Access is provided exclusively via @property.

    CLASS ATTRIBUTE:
        'total_threats' is shared by all LogEvent objects and 
        subclasses. Automatically incremented upon each instantiation.

    CONSTRUCTOR VALIDATION:
        Structurally invalid IPs raise a ValueError before allocation.
    """

    total_threats: int = 0

    def __init__(self, timestamp: str, ip_address: str, message: str) -> None:
        """
        Constructor for the LogEvent base class.

        Implements defensive validation: the object is not created 
        in an invalid state. It uses the setter via @property to reuse the 
        IP validation. Once validated, it increments the global counter.

        Args:
            timestamp (str): Event date and time (ex: "2024-01-15 08:23:11").
            ip_address (str): Source IPv4 address of the event.
            message (str): Text description of the security event.

        Raises:
            ValueError: If the ip_address does not have a valid IPv4 structure.
        """

        self.__timestamp: str = timestamp
        self.__message: str = message
        self.ip_address = ip_address
        LogEvent.total_threats += 1

    @property
    def timestamp(self) -> str:
        """Getter for the event timestamp. Read-only."""
        return self.__timestamp

    @property
    def ip_address(self) -> str:
        """Getter for the event IP address."""
        return self.__ip_address

    @ip_address.setter
    def ip_address(self, value: str) -> None:
        """
        Setter with validation for the IP address.

        Args:
            value (str): The IP address to set.

        Raises:
            ValueError: If the IP does not have a valid IPv4 format.
        """
        if not is_valid_ipv4(value):
            raise ValueError(
                f"Invalid IP: '{value}'. "
                f"Expected IPv4 structure (e.g., 192.168.1.10)."
            )
        self.__ip_address = value