import platform
import re
import socket
import subprocess


def detect_receiver_host() -> str:
    """Cross-platform local IP detection for the receiver UI.

    Supports Windows, macOS, and Linux by choosing the correct
    network commands based on the detected operating system.
    """
    host = "0.0.0.0"
    system = platform.system().lower()

    try:
        if system == "windows":
            output = subprocess.check_output(
                ["ipconfig"],
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            matches = re.findall(r"IPv4 Address[^:]*:\s*([0-9.]+)", output)

        elif system == "darwin":  # macOS
            # Try the simple route first - works on most macOS setups
            try:
                output = subprocess.check_output(
                    ["ipconfig", "getifaddr", "en0"],
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                ).strip()
                if output and not output.startswith("127."):
                    return output
            except (OSError, subprocess.CalledProcessError):
                pass

            # Fallback: parse ifconfig for all interfaces
            output = subprocess.check_output(
                ["ifconfig"],
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            matches = re.findall(r"inet\s+([0-9.]+)", output)

        else:  # Linux and other UNIX-like systems
            try:
                output = subprocess.check_output(
                    ["hostname", "-I"],
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                ).strip()
                matches = output.split()
            except (OSError, subprocess.CalledProcessError):
                # Fallback: parse ip addr
                output = subprocess.check_output(
                    ["ip", "addr"],
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                )
                matches = re.findall(r"inet\s+([0-9.]+)", output)

        for detected in matches:
            if detected and not detected.startswith("127."):
                host = detected
                break

    except (OSError, subprocess.CalledProcessError):
        # Last resort: use socket-based detection (works on all platforms)
        try:
            detected = socket.gethostbyname(socket.gethostname())
            if detected and not detected.startswith("127."):
                host = detected
        except OSError:
            pass

    return host
