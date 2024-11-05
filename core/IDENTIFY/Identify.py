import json
import gzip
import time
from datetime import datetime, timedelta, timezone
from termcolor import colored

def print_colored_log(message, color='white'):
    """Prints messages in a specified color."""
    print(colored(message, color))

def save_config_to_file(config, filename='./configfiles/config.json'):
    """Save configuration to a JSON configuration file."""
    try:
        print(colored("\n[*] Saving config to ",'cyan'), end='')
        print(colored(filename,'magenta'), end='')
        print(colored("...",'cyan'), end='')

        with open(filename, 'w') as f:
            json.dump(config, f, indent=4, default=str)
        print(colored("SUCCESS!",'green'))
    except Exception as e:
        print(colored("FAILURE!",'red'))
        print(colored(f"Error saving config to file: {str(e)}", 'blue'))
    print()