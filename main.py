import re
import sys
from models import is_valid_ipv4


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


from models import LogEvent, AuthFailureEvent, SqlInjectionEvent, PortScanEvent, classify_event
from analyzer import ThreatAnalyzer


def request_main_file() -> list[str]:
    """
    Request the main log file name and validate its content.

    Returns:
        list[str]: Lines read from the main log file.
    """
    while True:
        file_name: str = input("Enter the main log file name: ")

        try:
            with open(file_name, "r", encoding="utf-8") as file:
                raw_lines: list[str] = file.readlines()

            valid_log_found: bool = False

            for raw_line in raw_lines:
                if extract_log_event(raw_line) is not None:
                    valid_log_found = True
                    break

            if not valid_log_found:
                print("Warning: the selected file does not appear to be a valid log file. Please try again.")
                continue

            return raw_lines

        except FileNotFoundError:
            print("Warning: the selected file was not found. Please try again.")

        except OSError:
            print("Warning: an operating system error occurred while accessing the file.")


def load_whitelist() -> set[str]:
    """
    Load a secondary file containing safe IP addresses (UC2).

    Returns:
        set[str]: Set containing safe IP addresses.
    """
    while True:
        file_name: str = input("Enter the whitelist file name: ")

        safe_ips: set[str] = set()
        invalid_line_found: bool = False

        try:
            with open(file_name, "r", encoding="utf-8") as file:
                for line in file:
                    ip_address: str = line.strip()

                    if not ip_address:
                        continue

                    if ";" in ip_address or not is_valid_ipv4(ip_address):
                        invalid_line_found = True
                        break

                    safe_ips.add(ip_address)

            if invalid_line_found or len(safe_ips) == 0:
                print("Warning: the selected file does not appear to be a valid whitelist file. Please try again.")
                continue

            return safe_ips

        except FileNotFoundError:
            print("Warning: whitelist file not found. Please try again.")

        except OSError:
            print("Warning: an operating system error occurred while accessing the whitelist file.")


def process_log_lines(raw_lines: list[str], safe_ips: set[str]) -> list[LogEvent]:
    """
    Process raw log lines and return validated, classified threat objects.

    Args:
        raw_lines (list[str]): Raw lines read from the main log file.
        safe_ips (set[str]): Set containing safe IP addresses.

    Returns:
        list[LogEvent]: List of classified event objects.
    """
    processed_events: list[LogEvent] = []

    for raw_line in raw_lines:
        parsed = extract_log_event(raw_line)

        if parsed is None:
            continue

        if parsed["source_ip"] in safe_ips:
            continue

        event = classify_event(
            parsed["timestamp"],
            parsed["source_ip"],
            parsed["description"]
        )

        if event is not None:
            processed_events.append(event)

    return processed_events


def display_menu() -> None:
    """Displays the main CLI application menu (part of UC11)."""
    print(r"""
    _._     _,-'""`-._
    (,-.`._,'(       |\`-/|
        `-.-' \ )-`( , o o)
              `-    \`_`"'-
    """)
    print("\n" + "=" * 55)
    print("   THREAT ANALYZER CLI - Control Panel")
    print("=" * 55)
    print("  1. Load Log File and Whitelist")
    print("  2. View Total Detected Threats")
    print("  3. List Events (All or by Type)")
    print("  4. Detect Brute Force Attacks")
    print("  5. Perform IP Forensic Audit")
    print("  6. Exit and Export Final Report")
    print("=" * 55)


def run_listing_submenu(analyzer: ThreatAnalyzer) -> None:
    """
    Event listing submenu with filtering by type (UC7).

    Args:
        analyzer (ThreatAnalyzer): Orchestrator instance.
    """
    print(r"""
        /\_____/\
       /  o   o  \
      ( ==  ^  == )
       )         (
      (           )
     ( (  )   (  ) )
    (__(__)___(__)__)
    """)
    print("\n  --- Event Listing Options ---")
    print("  a) All events")
    print("  b) AuthFailureEvent only")
    print("  c) SqlInjectionEvent only")
    print("  d) PortScanEvent only")

    choice = input("\n  Select an option: ").strip().lower()

    if choice == "a":
        analyzer.list_events()
    elif choice == "b":
        analyzer.list_events(filter_type=AuthFailureEvent)
    elif choice == "c":
        analyzer.list_events(filter_type=SqlInjectionEvent)
    elif choice == "d":
        analyzer.list_events(filter_type=PortScanEvent)
    else:
        print("  Invalid option.")


def run() -> None:
    """
    Main function - orchestrates the entire application execution (UC11).

    The 'while True' loop keeps the menu active until the user exits.
    The interface is resilient to errors through try-except (M4_def §1.7).
    """
    print("\n" + "=" * 55)
    print("   THREAT ANALYZER CLI v1.0")
    print("   Security Log Analysis Tool")
    print("   ATEC | UC00606 Project")
    print("=" * 55)

    analyzer: ThreatAnalyzer = ThreatAnalyzer()

    while True:
        display_menu()

        try:
            choice: str = input("\n  Select an option (1-6): ").strip()

            if choice == "1":
                print("\n  --- Data Import ---")

                raw_lines: list[str] = request_main_file()

                safe_ips: set[str] = load_whitelist()

                events = process_log_lines(raw_lines, safe_ips)

                analyzer.load_events_from_list(events)

                print(f"\n  ✓ Processing completed: "
                      f"{len(events)} instantiated threats.")

            elif choice == "2":
                print("\n  --- Total Threat Count (UC8) ---")
                print(f"  Total instantiated threats in this session: "
                      f"{LogEvent.total_threats}")

            elif choice == "3":
                run_listing_submenu(analyzer)

            elif choice == "4":
                print("\n  --- Brute Force Detection (UC9) ---")
                brute_force = analyzer.detect_brute_force()

                if brute_force:
                    print(f"  ⚠ IPs classified as brute force "
                          f"(≥{5} authentication failures):")
                    for ip, count in sorted(brute_force.items()):
                        print(f"    • {ip:<20} → {count} attempts")
                else:
                    print("  No IP reached the brute-force threshold.")

            elif choice == "5":
                print("\n  --- IP Forensic Audit (UC10) ---")
                target_ip: str = input("  Enter the IP address to audit: ").strip()

                results = analyzer.search_by_ip(target_ip)

                if results:
                    print(f"\n  Events for {target_ip} "
                          f"(sorted by descending risk):\n")
                    for i, event in enumerate(results, start=1):
                        print(f"  {i:>3}. {event}")
                else:
                    print(f"  No events found for IP: {target_ip}")

            elif choice == "6":
                print("\n  Exporting final report before exiting...")
                analyzer.export_report("report.txt")
                print("\n  Session terminated. See you next time.")
                sys.exit(0)

            else:
                print("\n  ⚠ Invalid option. Please choose a number between 1 and 6.")

        except KeyboardInterrupt:
            print("\n\n  Interrupt detected. Exporting report...")
            analyzer.export_report("report_emergency.txt")
            sys.exit(0)

        except ValueError as e:
            print(f"\n  ⚠ Data error: {e}")

        except Exception as e:
            print(f"\n  ✗ Unexpected error: {e}")


if __name__ == "__main__":
    run()