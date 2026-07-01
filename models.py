from typing import Optional
from main import is_valid_ipv4

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
        """Getter for the event timestamp."""
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
                f"Expected IPv4 structure (ex: 192.168.1.10)."
            )
        self.__ip_address = value

    @property
    def message(self) -> str:
        """Getter for the event message."""
        return self.__message

    def calculate_risk(self) -> int:
        """
        Calculates the total risk of the event. Base value in parent class: 0.

        This method is overridden in all subclasses.
        Formula in subclasses: Total Risk = Base Risk + len(message).

        Returns:
            int: Calculated risk. Always 0 in the base class.
        """
        return 0

    def __str__(self) -> str:
        """
        User-friendly readable representation.
        Called by print(object) or str(object).
        Format: [TYPE] Date | IP | Risk: X | Message
        """
        event_type = self.__class__.__name__  # Name of the actual subclass
        return (
            f"[{event_type}] "
            f"{self.__timestamp} | "
            f"IP: {self.__ip_address} | "
            f"Risk: {self.calculate_risk()} | "
            f"{self.__message}"
        )

    def __repr__(self) -> str:
        """
        Technical object representation for debugging.
        Format: ClassName(timestamp='...', ip='...', risk=X)
        """
        return (
            f"{self.__class__.__name__}("
            f"timestamp='{self.__timestamp}', "
            f"ip='{self.__ip_address}', "
            f"risk={self.calculate_risk()})"
        )
class AuthFailureEvent(LogEvent):
    """
    Authentication failure event. Subclass of LogEvent.

    Base Risk = 5. Total Risk = 5 + len(message).
    Triggered when the message contains: "failed password" or "authentication".
    """