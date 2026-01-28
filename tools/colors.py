BRIGHT_BLACK   = "\033[90m"
BRIGHT_RED     = "\033[91m"
BRIGHT_GREEN   = "\033[92m"
BRIGHT_YELLOW  = "\033[93m"
BRIGHT_BLUE    = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN    = "\033[96m"
BRIGHT_WHITE   = "\033[97m"

RESET = "\033[0m"


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def print_color(text: str, color: str) -> None:
    print(color_text(text, color))
