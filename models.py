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

    __BASE_RISK: int = 5

    def __init__(self, timestamp: str, ip_address: str, message: str) -> None:
        """super() delegates the common __init__ to the parent class LogEvent."""
        super().__init__(timestamp, ip_address, message)

    def calculate_risk(self) -> int:
        """Overrides the parent class method. Returns: int Risk = 5 + len(message)."""
        return AuthFailureEvent.__BASE_RISK + len(self.message)


class SqlInjectionEvent(LogEvent):
    """
    SQL injection attempt event. Subclass of LogEvent.

    Base Risk = 10. Total Risk = 10 + len(message).
    Triggered when the message contains: "syntax error" or "union select".
    """

    __BASE_RISK: int = 10

    def __init__(self, timestamp: str, ip_address: str, message: str) -> None:
        super().__init__(timestamp, ip_address, message)

    def calculate_risk(self) -> int:
        """Returns: int Risk = 10 + len(message)."""
        return SqlInjectionEvent.__BASE_RISK + len(self.message)


class PortScanEvent(LogEvent):
    """
    Port scan event. Subclass of LogEvent.

    Base Risk = 3. Total Risk = 3 + len(message).
    Triggered when the message contains: "port scan" or "nmap".
    """

    __BASE_RISK: int = 3

    def __init__(self, timestamp: str, ip_address: str, message: str) -> None:
        super().__init__(timestamp, ip_address, message)

    def calculate_risk(self) -> int:
        """Returns: int Risk = 3 + len(message)."""
        return PortScanEvent.__BASE_RISK + len(self.message)
    
def classify_event(
    timestamp: str,
    ip_address: str,
    message: str
) -> Optional[LogEvent]:
    """
    Analyzes the message content and instantiates the correct subclass.

    Implements the triage logic: evaluates the textual content of the
    message using if/elif, converting it to lowercase with .lower() to
    prevent capitalization mismatches.

    Keywords defined by the specification:
        - AuthFailureEvent: "failed password", "authentication"
        - SqlInjectionEvent: "syntax error", "union select"
        - PortScanEvent: "port scan", "nmap"

    Args:
        timestamp (str): Event timestamp.
        ip_address (str): Source IP address.
        message (str): Event message (raw text).

    Returns:
        Optional[LogEvent]: An instance of the correct subclass,
            or None if the message does not match any known threat
            or if the IP is invalid (ValueError caught).
    """
    msg_lower: str = message.lower()

    try:
        # Triage Center: evaluates keywords (order = most critical first)
        if "syntax error" in msg_lower or "union select" in msg_lower:
            return SqlInjectionEvent(timestamp, ip_address, message)

        elif "failed password" in msg_lower or "authentication" in msg_lower:
            return AuthFailureEvent(timestamp, ip_address, message)

        elif "port scan" in msg_lower or "nmap" in msg_lower:
            return PortScanEvent(timestamp, ip_address, message)

        else:
            # Message not recognized as a known threat - ignored
            return None

    except ValueError:
        # Invalid IP detected by the LogEvent class setter
        return None