import socket
import ipaddress
from datetime import datetime

# Common port descriptions
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Alternate"
}


def validate_target(target):
    """Allow localhost and private network addresses only."""

    try:
        ip = ipaddress.ip_address(target)

        if not (ip.is_private or ip.is_loopback):
            return False

        return True

    except ValueError:
        try:
            ip = socket.gethostbyname(target)
            address = ipaddress.ip_address(ip)

            return address.is_private or address.is_loopback

        except socket.gaierror:
            return False


def scan_port(target, port):
    """Check whether a TCP port is open."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            return True

        return False

    except socket.error:
        return False

    finally:
        sock.close()


def start_scanner():

    print("=" * 55)
    print("          PYTHON PORT SCANNER")
    print("             CYBERSECURITY")
    print("=" * 55)

    target = input("\nEnter target IP/hostname: ").strip()

    if not validate_target(target):
        print("\nInvalid or unauthorized target.")
        print("Use localhost or an authorized private IP.")
        return

    try:
        start_port = int(input("Enter starting port (1-1024): "))
        end_port = int(input("Enter ending port (1-1024): "))

        if not (1 <= start_port <= end_port <= 1024):
            print("Invalid port range.")
            return

    except ValueError:
        print("Please enter valid port numbers.")
        return

    print("\nTarget:", target)
    print("Scan started:", datetime.now())
    print("-" * 55)

    open_ports = []

    for port in range(start_port, end_port + 1):

        if scan_port(target, port):

            service = COMMON_PORTS.get(port, "Unknown")

            print(f"[OPEN] Port {port} - {service}")

            open_ports.append(port)

    print("-" * 55)

    print("\nSCAN RESULTS")

    print("Target:", target)
    print("Ports scanned:", end_port - start_port + 1)
    print("Open ports:", len(open_ports))

    if open_ports:
        print("\nOpen Port List:")

        for port in open_ports:
            print(port, "-", COMMON_PORTS.get(port, "Unknown"))

    else:
        print("\nNo open ports detected.")

    print("\nScan completed:", datetime.now())

    print("=" * 55)


if __name__ == "__main__":
    start_scanner()