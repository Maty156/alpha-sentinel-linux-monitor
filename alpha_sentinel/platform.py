"""Platform detection for Alpha Sentinel."""

import sys


def detect() -> str:
    """
    Detect the operating system.
    
    Returns:
        'windows' or 'linux'
        
    Raises:
        RuntimeError: If OS is not Windows or Linux
    """
    if sys.platform.startswith("win"):
        return "windows"
    elif sys.platform.startswith("linux"):
        return "linux"
    else:
        raise RuntimeError(
            f"Unsupported OS: {sys.platform}. "
            "This tool runs on Windows (PowerShell 5.1+) or Linux (PowerShell 7+)."
        )


# Module-level platform for convenience
try:
    PLATFORM = detect()
except RuntimeError:
    PLATFORM = "unsupported"