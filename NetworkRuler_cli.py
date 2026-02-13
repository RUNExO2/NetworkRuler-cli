import argparse
import psutil
import subprocess
import os
import time
import ctypes
import sys as _sys # Use alias to avoid conflict with 'sys' in GUI import
from datetime import datetime
import json
from pathlib import Path
from datetime import datetime
# Attempt to import pydivert, make it optional
try:
    from pydivert import WinDivert, Packet, Protocol
    PYDIVERT_AVAILABLE = True
except ImportError:
    print("Warning: pydivert not found. Network throttling will not be available.")
    PYDIVERT_AVAILABLE = False
except Exception as e:
     print(f"Warning: Failed to import pydivert: {e}. Network throttling will not be available.")
     PYDIVERT_AVAILABLE = False

# Attempt to import process_viewer, make it optional
try:
    import process_viewer as pv
    PROCESS_VIEWER_AVAILABLE = True
except ImportError:
    print("Warning: process_viewer.py not found. Advanced process commands ('proc') and '--task' will not be available.")
    PROCESS_VIEWER_AVAILABLE = False
except Exception as e:
     print(f"Warning: Failed to import process_viewer.py: {e}. Advanced process commands ('proc') and '--task' will not be available.")
     PROCESS_VIEWER_AVAILABLE = False


profile_name = ""
settings = ""
# Removed the global LIMIT_RATE_BYTES_PER_SEC as it's defined inside the throttle function now
command_history = []

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def add_to_path(new_path):
    """Adds a given path to the user's environment PATH variable via PowerShell."""
    username = os.getlogin()
    current_user_path = os.environ.get("PATH", "")

    if new_path not in current_user_path:
        print(f"Attempting to add {new_path} to PATH for user: {username}")
        try:
            # Use elevated PowerShell command
            # This might require UAC prompt if not already admin
            subprocess.run([
                "powershell",
                "-Command",
                f"[Environment]::SetEnvironmentVariable('PATH', [Environment]::GetEnvironmentVariable('PATH', 'User') + ';{new_path}', 'User')"
            ], check=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW) # Use shell=True and CREATE_NO_WINDOW to potentially hide window

            print(f"✅ Added {new_path} to PATH for user: {username}")
            log_activity(f"Added {new_path} to PATH for user: {username}")
        except subprocess.CalledProcessError:
            print(f"\n❌ Auto-adding '{new_path}' to PATH failed, sweetheart. You might not have permission or UAC was denied.")
            print(f"👉 Try running the application as administrator.")
            print(f"👉 Or run this manually in PowerShell (as admin):")
            print(f"[Environment]::SetEnvironmentVariable('PATH', [Environment]::GetEnvironmentVariable('PATH', 'User') + ';{new_path}', 'User', 'Machine') # Use 'Machine' if you want it system-wide (requires admin)")
            log_activity(f"Failed to add {new_path} to PATH")
        except Exception as e:
             print(f"\n❌ An unexpected error occurred while adding to PATH: {e}")
             log_activity(f"Error adding {new_path} to PATH: {e}")
    else:
        print(f"'{new_path}' is already in the user's PATH.")
        log_activity(f"{new_path} already in PATH")


# Define ALIAS_FILE relative to the script's directory
ALIAS_FILE = Path(__file__).resolve().parent / "aliases.json"
LOG_FILE = Path(__file__).resolve().parent / "activity_log.txt"


def load_aliases():
    """Loads command aliases from the aliases.json file."""
    if ALIAS_FILE.exists():
        try:
            with open(ALIAS_FILE, 'r') as f:
                aliases = json.load(f)
            # Ensure aliases is a dictionary, handle corrupted file
            if not isinstance(aliases, dict):
                print(f"Warning: aliases.json is corrupted. Resetting aliases.")
                return {}
            return aliases
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading aliases.json: {e}. Starting with empty aliases.")
            return {}
    return {} # Return empty dict if file doesn't exist

def save_aliases(aliases):
    """Saves command aliases to the aliases.json file."""
    try:
        with open(ALIAS_FILE, 'w') as f:
            json.dump(aliases, f, indent=4) # Use indent for readability
    except IOError as e:
        print(f"Error saving aliases.json: {e}")

def resolve_alias(args):
    """Resolves an alias in the input arguments."""
    # Handle 'log' as a special case if it's implemented directly in main
    # If log opens a file, it's better handled in main or a dedicated function
    # Let's keep the CLI 'log' command separate from alias resolution for clarity
    # The GUI calls openLog directly, which is better.

    if not args:
        return args

    aliases = load_aliases()
    if args[0] in aliases:
        # Replace the alias with its full command string, keep subsequent args
        full_command = aliases[args[0]].split()
        resolved_args = full_command + args[1:]
        # print(f"Resolved alias '{args[0]}' to '{' '.join(resolved_args)}'") # Optional debug print
        return resolved_args
    # No alias found, return original args
    return args

def set_alias(alias, real_command_string):
    """Sets an alias for a real command string."""
    # Ensure real_command_string is treated as a single command value
    aliases = load_aliases()
    aliases[alias] = real_command_string # Store the full string
    save_aliases(aliases)
    print(f"Alias set: '{alias}' -> '{real_command_string}'")
    log_activity(f"Set alias: {alias} -> {real_command_string}")


def list_all():
    """Lists all running processes and services."""
    print("\n[Processes]:")
    try:
        # Use psutil for processes
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                pinfo = proc.info
                # Handle potential None for username if access denied
                username_display = pinfo.get('username', 'N/A') if pinfo.get('username') else 'N/A'
                print(f"{pinfo.get('pid', 'N/A'):<10} {pinfo.get('name', 'N/A'):<30} {username_display}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process may have exited or permissions issue
                continue
    except Exception as e:
        print(f"Error listing processes: {e}")


    print("\n[Services]:")
    try:
        # Use subprocess for services (Windows specific 'sc')
        # Capture stderr as well in case of permission issues
        output = subprocess.check_output(
            'sc query type= service state= all',
            shell=True,
            text=True, # Decode output to text
            stderr=subprocess.STDOUT
        )
        lines = output.strip().splitlines()
        service_name = None
        # Parse sc query output
        for line in lines:
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                if service_name: # Print previous service if found
                     print(service_name)
                service_name = line.split(":", 1)[1].strip()
            elif line.startswith("STATE"):
                 if service_name:
                      state_info = line.split(":", 1)[1].strip()
                      # Optional: include state, e.g., f"{service_name} ({state_info.split()[0]})"
                      print(service_name)
                      service_name = None # Reset after printing
        if service_name: # Print the last service
             print(service_name)

    except subprocess.CalledProcessError as e:
         print(f"Error listing services: {e.output.strip()}")
         print("(Listing services requires administrator privileges)")
    except Exception as e:
        print(f"Error listing services: {e}")
    log_activity("Listed all processes and services")


def list_apps(prefix=None):
    """Lists application processes, optionally filtered by name prefix."""
    print("\n[Applications]:")
    try:
        # Heuristic: Assume processes with a GUI are 'apps'. psutil doesn't directly provide this.
        # A simpler approach is just listing processes, maybe filtering system ones, or using a hardcoded list.
        # Let's stick to listing process names, filtered by prefix as requested.
        # A more robust check might involve trying to get the main window handle (Windows specific) or checking CPUTime/connections.
        seen_pids = set()
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pinfo = proc.info
                pid = pinfo.get('pid')
                name = pinfo.get('name')
                if pid is None or name is None or pid in seen_pids:
                    continue

                # Simple filter: exclude common system processes? Too complex/fragile.
                # Just list all processes matching prefix.
                if prefix is None or name.lower().startswith(prefix.lower()):
                    print(f"{pid:<10} {name}")
                    seen_pids.add(pid) # Avoid duplicates if iterating different ways
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        print(f"Error listing applications: {e}")
    log_activity(f"Listed applications (prefix: {prefix})")


def list_services():
    """Lists installed services."""
    print("\n[Services]:")
    try:
        output = subprocess.check_output('sc query type= service state= all', shell=True, text=True, stderr=subprocess.STDOUT)
        lines = output.strip().splitlines()
        service_name = None
        for line in lines:
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                if service_name:
                    print(service_name)
                service_name = line.split(":", 1)[1].strip()
            elif line.startswith("STATE"):
                 if service_name:
                      # Optional: include state
                      print(service_name)
                      service_name = None
        if service_name:
             print(service_name)

    except subprocess.CalledProcessError as e:
         print(f"Error listing services: {e.output.strip()}")
         print("(Listing services requires administrator privileges)")
    except Exception as e:
        print(f"Error listing services: {e}")
    log_activity("Listed services")


def kill_process(name_or_pid):
    """Kills a process by name or PID, or stops a service by name."""
    killed_any = False
    pid_found = None

    # 1. Try killing as a process by PID first
    try:
        pid = int(name_or_pid)
        try:
            proc = psutil.Process(pid)
            print(f"Attempting to kill process: {proc.name()} (PID: {pid})...")
            proc.terminate() # Or use proc.kill() for immediate termination
            # Wait a bit for process to terminate
            try:
                proc.wait(timeout=3)
                print(f"Killed process: {proc.name()} (PID: {pid})")
            except psutil.TimeoutExpired:
                print(f"Process {pid} did not terminate in time, forcing kill...")
                proc.kill()
                print(f"Forcibly killed process: {proc.name()} (PID: {pid})")
            killed_any = True
            pid_found = pid
        except psutil.NoSuchProcess:
            print(f"No process found with PID: {pid}.")
        except psutil.AccessDenied:
            print(f"Access denied to kill process with PID: {pid}. Try running as administrator.")
        except Exception as e:
             print(f"Error killing process {pid}: {e}")

    except ValueError:
        # 2. If not a PID, try killing as a process by name
        process_name = name_or_pid.lower()
        print(f"Attempting to kill processes with name: {process_name}...")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == process_name:
                    print(f"  Found process: {proc.info['name']} (PID: {proc.info['pid']})...")
                    try:
                        proc.terminate()
                        try:
                             proc.wait(timeout=3)
                             print(f"  Killed process: {proc.info['name']} (PID: {proc.info['pid']})")
                        except psutil.TimeoutExpired:
                             print(f"  Process {proc.info['pid']} did not terminate in time, forcing kill...")
                             proc.kill()
                             print(f"  Forcibly killed process: {proc.info['name']} (PID: {proc.info['pid']})")
                        killed_any = True
                    except psutil.AccessDenied:
                        print(f"  Access denied to kill process {proc.info['pid']}. Try running as administrator.")
                    except Exception as e:
                        print(f"  Error killing process {proc.info['pid']}: {e}")

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                 continue # Process might have exited between iter and access

    # 3. If no process was killed, try stopping as a service by name
    if not killed_any:
        service_name = name_or_pid
        print(f"No process '{name_or_pid}' found. Attempting to stop service: '{service_name}'...")
        try:
            # Use shell=True for simple command execution, may require admin
            result = subprocess.run(
                f'sc stop "{service_name}"',
                shell=True,
                check=True, # Raise CalledProcessError for non-zero exit codes
                stdout=subprocess.PIPE, # Capture stdout
                stderr=subprocess.PIPE, # Capture stderr
                text=True, # Decode output
                creationflags=subprocess.CREATE_NO_WINDOW # Try to hide window
            )
            print(f"Stopped service: {service_name}")
            killed_any = True
        except subprocess.CalledProcessError as e:
            # Check stderr/stdout for specific error messages
            output = (e.stdout + e.stderr).strip()
            if "The specified service does not exist as an installed service" in output:
                 print(f"❌ No process, service, or exact match found for '{name_or_pid}'.")
            elif "Access is denied" in output or "run as an administrator" in output:
                 print(f"Access denied to stop service '{service_name}'. Try running as administrator.")
            else:
                 print(f"Error stopping service '{service_name}': {output}")
        except Exception as e:
            print(f"An unexpected error occurred while trying to stop service '{service_name}': {e}")

    if killed_any:
        log_activity(f"Killed/Stopped: {name_or_pid}")
    else:
        log_activity(f"Kill/Stop target not found: {name_or_pid}")


def get_target_ips(proc_name):
    """Finds remote IP addresses for connections belonging to a process by name."""
    target_ips = set()
    found_pid = None
    try:
        # Find PID by name first
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == proc_name.lower():
                    found_pid = proc.info['pid']
                    break  # Found the first one
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                 continue

        if found_pid is None:
            print(f"Process '{proc_name}' not found.")
            log_activity(f"Get target IPs: Process '{proc_name}' not found")
            return target_ips  # Return empty set

        # Get connections for the found PID -- use net_connections() instead of connections()
        try:
            p = psutil.Process(found_pid)
            print(f"Looking up connections for {proc_name} (PID: {found_pid})...")
            for conn in p.net_connections(kind='inet'):
                # 'inet' kind includes TCP and UDP for both IPv4 and IPv6
                if conn.raddr:  # Check if remote address exists
                    target_ips.add(conn.raddr.ip)
        except psutil.AccessDenied:
            print(f"Access denied to get connections for process {found_pid}. Try running as administrator.")
        except psutil.NoSuchProcess:
             print(f"Process {found_pid} disappeared while fetching connections.")
        except Exception as e:
            print(f"Error fetching connections for PID {found_pid}: {e}")

    except Exception as e:
        print(f"Error finding process {proc_name}: {e}")

    ip_list_str = ", ".join(list(target_ips)) if target_ips else "None found."
    print(f"Target IPs for {proc_name}: {ip_list_str}")
    log_activity(f"Got target IPs for {proc_name}: {ip_list_str}")
    return target_ips

def monitor_bandwidth():
    """Monitors and prints real-time bandwidth usage."""
    print("\nReal-time Bandwidth Monitor (Press Ctrl+C to quit):")
    try:
        # Get initial counters
        last_counters = psutil.net_io_counters()
        last_time = time.time()

        while True:
            time.sleep(1) # Wait for 1 second

            current_counters = psutil.net_io_counters()
            current_time = time.time()

            # Calculate delta over the time period
            time_delta = current_time - last_time
            sent_delta = current_counters.bytes_sent - last_counters.bytes_sent
            recv_delta = current_counters.bytes_recv - last_counters.bytes_recv

            if time_delta > 0:
                # Calculate speed in MB/s
                sent_speed_mbps = (sent_delta / time_delta) / (1024 * 1024)
                recv_speed_mbps = (recv_delta / time_delta) / (1024 * 1024)
                print(f"Sent: {sent_speed_mbps:.2f} MB/s | Received: {recv_speed_mbps:.2f} MB/s")
            else:
                 # Should not happen with time.sleep(1), but safety check
                 print("Sent: 0.00 MB/s | Received: 0.00 MB/s")


            # Update for the next iteration
            last_counters = current_counters
            last_time = current_time

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
        log_activity("Bandwidth monitoring stopped")
    except Exception as e:
        print(f"Error during bandwidth monitoring: {e}")
        log_activity(f"Bandwidth monitoring error: {e}")

def save_profile(profile_name, settings_string, command_history=None):
    """Saves commands/settings to a named JSON profile."""
    print(f"Saving profile: {profile_name}")
    profile_dir = Path(__file__).resolve().parent / "profiles"
    profile_dir.mkdir(exist_ok=True) # Create profiles directory if it doesn't exist

    profile_path = profile_dir / f"{profile_name}.json"

    # Split the settings string into a list of commands
    # Ensure each command part is stripped of whitespace
    commands_list = [cmd.strip() for cmd in settings_string.split(',') if cmd.strip()]

    # If command_history is not explicitly provided (e.g., from GUI), use the commands_list
    # If called from CLI main, command_history is passed, but for GUI compatibility, handle None
    if command_history is None:
        command_history = commands_list # Or maybe capture actual history from main? Sticking to settings for now.

    profile_data = {
        "profile_name": profile_name,
        "settings": settings_string, # Keep the original string for reference
        "commands": commands_list # Store as a list of commands to execute
    }

    try:
        with open(profile_path, "w", encoding="utf-8") as profile_file:
            json.dump(profile_data, profile_file, indent=4) # Use indent for readability

        print(f"Profile '{profile_name}' saved successfully to {profile_path}")
        log_activity(f"Saved profile: {profile_name}")
    except IOError as e:
        print(f"Error saving profile '{profile_name}': {e}")
        log_activity(f"Error saving profile {profile_name}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while saving profile '{profile_name}': {e}")
        log_activity(f"Error saving profile {profile_name}: {e}")


def load_profile(profile_name):
    """Loads a profile and executes the commands within it."""
    print(f"Loading profile: {profile_name}")
    log_activity(f"Loading profile: {profile_name}")
    profile_dir = Path(__file__).resolve().parent / "profiles"
    profile_path = profile_dir / f"{profile_name}.json"

    if not profile_path.exists():
        print(f"Profile '{profile_name}' not found at {profile_path}")
        log_activity(f"Load profile failed: '{profile_name}' not found.")
        return

    try:
        with open(profile_path, "r", encoding="utf-8") as profile_file:
            profile_data = json.load(profile_file)

        # Validate profile data structure
        if not isinstance(profile_data, dict) or "commands" not in profile_data or not isinstance(profile_data["commands"], list):
            print(f"Error: Profile file '{profile_name}.json' has an invalid format.")
            log_activity(f"Load profile failed: Invalid format for '{profile_name}'.")
            return

        print(f"Profile '{profile_data.get('profile_name', profile_name)}' loaded successfully.")
        # Do NOT log here again, log_activity is called for each executed command below

        # Execute commands listed in the profile
        print("\nExecuting commands from profile:")
        for command_str in profile_data.get("commands", []):
            print(f"> {command_str}")
            # Split command string back into args and call main() recursively
            # This is how the original code seemed to handle execution within the CLI
            # Be cautious of deep recursion or complex command dependencies
            try:
                command_args = command_str.split()
                # Temporarily modify sys.argv to trick main() into processing these args
                # Save original sys.argv
                original_argv = _sys.argv
                _sys.argv = ['nr'] + command_args
                main() # Call main to execute the command
            except Exception as e:
                 print(f"Error executing command '{command_str}' from profile: {e}")
                 log_activity(f"Error executing profile command '{command_str}': {e}")
            finally:
                # Restore original sys.argv after the command is processed by main()
                _sys.argv = original_argv

        print("Profile command execution finished.")
        log_activity(f"Profile '{profile_name}' commands executed.")

    except json.JSONDecodeError:
        print(f"Error: Profile file '{profile_name}.json' is not valid JSON.")
        log_activity(f"Load profile failed: Invalid JSON in '{profile_name}'.")
    except IOError as e:
        print(f"Error reading profile file '{profile_name}.json': {e}")
        log_activity(f"Error reading profile {profile_name}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while loading or executing profile '{profile_name}': {e}")
        log_activity(f"Error loading/executing profile {profile_name}: {e}")


def stealth_mode():
    """Attempts to hide the console window (Windows specific)."""
    if os.name == 'nt': # Check if running on Windows
        try:
            # Get handle of the current console window
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                # Hide the window
                ctypes.windll.user32.ShowWindow(hwnd, 0) # 0 = SW_HIDE
            print("Attempted to hide console window.")
            log_activity("Enabled stealth mode (hid console).")
        except Exception as e:
            print(f"Error hiding console: {e}")
            log_activity(f"Error enabling stealth mode: {e}")
    else:
        print("Stealth mode (hiding console) is only available on Windows.")
        log_activity("Attempted stealth mode (not Windows).")


def log_activity(activity):
    """Appends an activity entry with timestamp to the log file."""
    # Avoid logging the log activity itself to prevent infinite loop/noise
    # Also avoid logging profile save/load calls from within save/load functions
    # The check in the GUI should handle not calling log_activity on profile save/load button clicks.
    # Here, we filter based on the activity string content.
    if activity.startswith("Saved profile:") or activity.startswith("Loading profile:"):
        # print(f"Skipping log for activity: {activity}") # Optional debug
        return

    try:
        # Ensure the log file directory exists if needed (unlikely for script root)
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Append to file, create if it doesn't exist
        with open(LOG_FILE, 'a', encoding='utf-8') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {activity}\n")
        # print(f"Activity logged.") # Optional confirmation, can be noisy
    except IOError as e:
        print(f"Error writing to log file {LOG_FILE}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while logging: {e}")


# The original manual_add_to_path seems redundant if install_path works or user runs manually.
# Let's keep install_path as the primary method in CLI. The GUI has an explicit button for it.
# def manual_add_to_path(path=None):
#    ... (removed or commented out) ...


def run_cmd(title, command):
    """Runs a shell command and prints formatted output."""
    print(f"\n--- {title} ---")
    log_activity(f"Running command: {command}")
    try:
        # Use subprocess.run for better control over capture
        result = subprocess.run(
            command,
            shell=True, # Execute command through the shell
            check=True, # Raise CalledProcessError on non-zero exit
            stdout=subprocess.PIPE, # Capture stdout
            stderr=subprocess.PIPE, # Capture stderr
            text=True, # Decode output as text
            creationflags=subprocess.CREATE_NO_WINDOW # Try to hide command window
        )
        print(result.stdout.strip())
        # Optionally print stderr if it's not empty, even on success
        if result.stderr:
             print("--- STDERR ---")
             print(result.stderr.strip())

        print(f"--- {title} Finished ---")
        # Log successful command execution (activity already logged before run)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Failed to run {title}:")
        print(e.stdout.strip())
        if e.stderr:
             print("--- STDERR ---")
             print(e.stderr.strip())
        print(f"--- {title} Failed ---")
        log_activity(f"Command failed: {command} - Error: {e.returncode}")
    except FileNotFoundError:
         print(f"\n❌ Error: Command not found. Make sure '{command.split()[0]}' is in your system PATH.")
         print(f"--- {title} Failed ---")
         log_activity(f"Command not found: {command}")
    except Exception as e:
        print(f"\n❌ An unexpected error occurred while running {title}: {e}")
        print(f"--- {title} Failed ---")
        log_activity(f"Error running command {command}: {e}")


def handle_net_commands(args):
    """Maps and runs predefined network commands based on arguments."""
    # Define command map with argument tuples as keys
    # The longest matching key should be used for commands with multiple args like ('-s', 'interfaces', 'netsh')
    cmd_map = {
        ('-f', 'dns'): ("Flush DNS", "ipconfig /flushdns"),
        ('-r', 'dns'): ("Register DNS", "ipconfig /registerdns"),
        ('-d', 'ip'): ("Release IP", "ipconfig /release"),
        ('-renew', 'ip'): ("Renew IP", "ipconfig /renew"),
        ('-s', 'config'): ("IP Configuration (All)", "ipconfig /all"),
        ('-s', 'interfaces'): ("Active IP Interfaces", "ipconfig"),
        ('-show', 'firewall'): ("Show Firewall Status", "netsh advfirewall show allprofiles"),
        ('-reset', 'firewall'): ("Reset Firewall", "netsh advfirewall reset"),
        ('-on', 'firewall'): ("Enable Firewall", "netsh advfirewall set allprofiles state on"),
        ('-off', 'firewall'): ("Disable Firewall", "netsh advfirewall set allprofiles state off"),
        # Note: netsh interface show interface is a single command, args should be exactly these
        ('-s', 'interfaces', 'netsh'): ("Netsh Interfaces", "netsh interface show interface"),
        ('-s', 'address'): ("Show IP Addresses", "netsh interface ip show addresses"),
        ('-reset', 'winsock'): ("Reset Winsock", "netsh winsock reset"),
        ('-reset', 'tcp'): ("Reset TCP/IP Stack", "netsh int ip reset"),
        ('-reset', 'proxy'): ("Reset Proxy", "netsh winhttp reset proxy"),
        ('-show', 'proxy'): ("Show Proxy", "netsh winhttp show proxy"),
        ('-off', 'proxy'): ("Disable Proxy", "netsh winhttp reset proxy"),
    }

    # Find the longest matching key from cmd_map in the beginning of args
    best_match = None
    for key_tuple in sorted(cmd_map.keys(), key=len, reverse=True):
        if len(args) >= len(key_tuple) and tuple(args[:len(key_tuple)]) == key_tuple:
            best_match = key_tuple
            break # Found the longest match

    if best_match:
        title, command = cmd_map[best_match]
        run_cmd(title, command)
    else:
        print("❓ Unknown network command, love.")
        print("Available commands (use 'nr <command>'):")
        # Print available command args for help
        for key_tuple in sorted(cmd_map.keys(), key=lambda x: ' '.join(x)):
             print(f"  {' '.join(key_tuple)}")
        log_activity(f"Unknown network command: {' '.join(args)}")

def test_wireless_signals(output_func=print):
    log_activity("Testing wireless signals")
    output_func("\n📶 [Wi-Fi Signal Info]:")

    try:
        output = subprocess.check_output(["netsh", "wlan", "show", "interfaces"],
                                           stderr=subprocess.STDOUT, text=True)

        if "There is no wireless interface on the system" in output:
            output_func("❌ No wireless interfaces found.")
            return

        lines = output.splitlines()
        interface_found = False
        for line in lines:
            line = line.strip()
            if "State" in line and "connected" in line.lower():
                interface_found = True
            if interface_found:
                if "Name" in line:
                    output_func("🔧 " + line)
                elif "Description" in line:
                    output_func("💻 " + line)
                elif "SSID" in line and "BSSID" not in line:
                    output_func("📡 " + line)
                elif "Signal" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        signal_strength = parts[1].strip()
                        output_func(f"📶 Signal Strength: {signal_strength}")
                        try:
                            strength_value = int(signal_strength.replace("%", ""))
                            if strength_value >= 80:
                                level = "Excellent"
                            elif strength_value >= 60:
                                level = "Good"
                            elif strength_value >= 40:
                                level = "Mid"
                            else:
                                level = "Poor"
                            output_func(f"📊 Quality: {level}")
                        except ValueError:
                            pass
                elif any(key in line for key in ["Radio type", "Channel", "Receive rate", "Transmit rate", "Authentication", "Cipher"]):
                    output_func("📡 " + line)
            if interface_found and (not line or line.startswith("Interface name:")):
                 break

        if not interface_found:
             output_func("❌ Wi-Fi interface found but not connected.")

    except FileNotFoundError:
        output_func("❌ Error: 'netsh' command not found. Make sure it's in your system PATH.")
    except subprocess.CalledProcessError as e:
        output_func(f"❌ netsh error: {e.output.strip()}")
        output_func("(Wi-Fi signal test requires administrator privileges)")
    except Exception as e:
        output_func(f"❌ Unexpected error during Wi-Fi signal test: {e}")

    output_func("\n🔵 [Bluetooth Info]:\n")
    try:
        result = subprocess.run(
            ["powershell", "-Command", "Get-PnpDevice -Class Bluetooth"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            output_func(result.stdout.strip())
        else:
            output_func(f"PowerShell error (Exit Code {result.returncode}):")
            output_func(result.stderr.strip() or result.stdout.strip() or "No output.")
            if "run as an administrator" in (result.stderr + result.stdout).lower():
                 output_func("(Getting Bluetooth info might require administrator privileges)")
    except FileNotFoundError:
        output_func("❌ Error: 'powershell' command not found.")
    except subprocess.TimeoutExpired:
        output_func("❌ PowerShell command timed out.")
    except Exception as e:
        output_func(f"❌ Failed to get Bluetooth info: {e}")


def show_help():
    """Displays the help message."""
    help_text = """
    Usage: network ruler <command> [options]

    Main Commands:
    --help                         | Show this help message
    --list                         | List all processes and services
    app --list [prefix]            | List only applications (optionally filtered)
    srv --list                     | List only services
    --kill <name|pid>              | Kill a process by name/PID or stop a service by name
    --limit <process.exe> <speed>  | Throttle network speed for a process (ex: 5mb) (Requires Admin & pydivert)
    background app --limit <speed> | Throttle all background apps (not implemented yet)
    monitor --live                 | Monitor real-time system-wide bandwidth usage
    save <profile_name> <settings> | Save settings/commands (comma-separated) to a profile
    load <profile_name>            | Load settings from a profile and execute commands
    stealth                        | Hide the console window (Windows only)
    log                            | Opens activity log file

    Process Viewer Commands (proc):
    (Requires process_viewer.py)
    proc list [sort_key]           | List processes sorted by CPU (default), 'mem' or 'name'
    proc info <PID>                | Show detailed info about a process
    proc tree                      | Display a tree view of processes
    proc openfiles <PID>           | List open files for a process
    proc connections <PID>         | Display network connections for a process
    proc env <PID>                 | Show environment variables for a process
    proc suspend <PID>             | Suspend the process
    proc resume <PID>              | Resume the suspended process
    proc priority <PID> <level>    | Set process priority (levels: low, below, normal, above, high, realtime)
    proc monitor                   | Start a system resource monitor

    Network Commands (alias for netsh/ipconfig, use 'nr <command>'):
    nr -f dns                      | Flush DNS cache
    nr -r dns                      | Register DNS
    nr -d ip                       | Release IP address
    nr -renew ip                   | Renew IP address
    nr -s config                   | Show full IP configuration
    nr -s interfaces               | Show basic IP interfaces
    nr -show firewall              | Show current firewall status (Requires Admin)
    nr -reset firewall             | Reset Windows Firewall to default (Requires Admin)
    nr -on firewall                | Enable Windows Firewall (Requires Admin)
    nr -off firewall               | Disable Windows Firewall (Requires Admin)
    nr -s interfaces netsh         | Show all network interfaces via netsh
    nr -s address                  | Display IP address assignments
    nr -reset winsock              | Reset Winsock catalog (Requires Admin)
    nr -reset tcp                  | Reset TCP/IP stack (Requires Admin)
    nr -reset proxy                | Reset WinHTTP proxy settings
    nr -show proxy                 | Display current WinHTTP proxy settings
    nr -off proxy                  | Disable WinHTTP proxy

    Utility Commands:
    set-alias <alias> <real_command_string> | Create a persistent alias (stores in aliases.json)
    install-path                     | Add the script directory to the user's system PATH (Requires Admin)
    test --signals                   | Test and display wireless and Bluetooth signal information (Requires Admin for Wi-Fi)

    Examples:
    network ruler --list
    network ruler app --list chrome
    network ruler --kill 1234
    network ruler --kill myapp.exe
    network ruler --kill "My Service"
    network ruler --limit chrome.exe 10      | Throttle Chrome to 10 Mbps (note: speed is just the number)
    network ruler monitor --live
    network ruler save mynetsettings "-f dns, -renew ip, -reset winsock"
    network ruler load mynetsettings
    network ruler stealth
    nr -s config
    proc list mem
    proc info 5678
    set-alias l --list
    l                                | Executes --list via alias

    Alias Info:
    Aliases are stored in aliases.json in the script directory.
    You can add the script's directory to your system PATH using 'install-path' or manually.
    This allows running commands from any directory using 'network ruler' or your set aliases (like 'nr' if aliased).

    """
    print(help_text)
    log_activity("Showed help")

def main():
    """Main function for parsing arguments and executing commands."""
    global profile_name, settings
    known_builtins = ["--list", "--kill", "--limit", "app", "srv", "background", "monitor", "save", "load", "stealth", "log", "proc", "set-alias", "install-path", "test"]
    # Log the raw command line arguments received
    log_activity("CLI command received: " + " ".join(_sys.argv))

    # Check for initial --help regardless of alias
    if '--help' in _sys.argv or '-h' in _sys.argv: # Also check for -h
        show_help()
        return # Exit after showing help

    # Separate the script name from the arguments
    # args = _sys.argv[1:]

    # --- Argument Parsing ---
    # Using argparse can make CLI argument handling more robust.
    # However, the original code parses manually and uses recursion for profiles/aliases.
    # Sticking close to the original structure for minimal diff, but adding basic parsing logic.

    # Get arguments excluding the script name
    raw_args = _sys.argv[1:]
    args = raw_args # Start with raw args

    # Resolve aliases *only if* the first argument is not a known built-in command
    # This prevents resolving 'proc' or '--list' if they happen to be aliases
    # Known built-ins: --list, --kill, --limit, app, srv, background, monitor, save, load, stealth, log, proc, set-alias, install-path, test
    if args and args[0] not in known_builtins and not args[0].startswith('-'):
         args = resolve_alias(args)
         if not args: # If alias resolution returned empty args (e.g. alias not found)
              return # Stop execution


    # --- Command Execution ---

    if not args:
        print("Missing command, honey. Use --help")
        log_activity("CLI command received with no arguments")
        return

    command = args[0].lower() # Use lowercase for command matching

    if command == '--list':
        list_all()

    elif command == '--kill':
        if len(args) >= 2:
            kill_process(args[1])
        else:
            print("Usage: --kill <name|pid>")
            log_activity("CLI command '--kill' missing argument")

    elif command == '--limit':
        if len(args) >= 3:
            proc_name = args[1]
            speed_str = args[2].lower().replace('mb', '').replace('m', '')
            try:
                mb = int(speed_str)
                # The throttle_process function itself prints success/failure
                throttle_process(proc_name, mb)
            except ValueError:
                print("Invalid throttle speed format. Use a number (e.g., '5').")
                log_activity(f"CLI command '--limit' invalid speed: {args[2]}")
        else:
            print("Usage: --limit <process.exe> <speed_mbps>")
            log_activity("CLI command '--limit' missing arguments")

    elif command == 'app' and len(args) > 1 and args[1].lower() == '--list':
        prefix = args[2] if len(args) >= 3 else None
        list_apps(prefix)

    elif command == 'srv' and len(args) > 1 and args[1].lower() == '--list':
        list_services()

    elif command == 'background' and len(args) >= 4 and args[1].lower() == 'app' and args[2].lower() == '--limit':
         # Example: network ruler background app --limit 5mb
         speed_str = args[3].lower().replace('mb', '').replace('m', '')
         try:
            mb = int(speed_str)
            throttle_background_apps(mb)
         except ValueError:
             print("Invalid throttle speed format. Use a number (e.g., '1').")
             log_activity(f"CLI command 'background app --limit' invalid speed: {args[3]}")


    elif command == 'monitor' and len(args) > 1 and args[1].lower() == '--live':
        monitor_bandwidth()

    elif command == 'save':
        # Usage: save <profile_name> <settings_string>
        if len(args) >= 3:
             profile_name_arg = args[1]
             # Join remaining arguments to form the settings string
             settings_string = " ".join(args[2:])
             save_profile(profile_name_arg, settings_string)
        else:
            print("Usage: save <profile_name> <settings_string (comma-separated)>")
            log_activity("CLI command 'save' missing arguments")

    elif command == 'load':
        # Usage: load <profile_name>
        if len(args) >= 2:
            profile_name_arg = args[1]
            load_profile(profile_name_arg)
        else:
            print("Usage: load <profile_name>")
            log_activity("CLI command 'load' missing argument")

    elif command == 'stealth':
        stealth_mode()

    elif command == 'log':
        # Opens the activity_log.txt file
        try:
            # Use os.startfile on Windows to open with default application
            log_file_path = LOG_FILE.as_posix() # Get cross-platform path string
            if os.path.exists(log_file_path):
                 os.startfile(log_file_path)
                 print(f"Opened log file: {log_file_path}")
                 log_activity(f"Opened log file from CLI")
            else:
                 print(f"Log file not found: {log_file_path}")
                 log_activity(f"Attempted to open non-existent log file")
        except AttributeError:
            print("Opening log file with default application is only supported on Windows.")
        except FileNotFoundError:
             print(f"Log file not found: {log_file_path}")
             log_activity(f"Attempted to open non-existent log file")
        except Exception as e:
            print(f"Error opening log file: {e}")
            log_activity(f"Error opening log file: {e}")

    elif command == 'set-alias':
        # Usage: set-alias <alias> <real_command_string>
        if len(args) >= 3:
            alias = args[1]
            # The rest of the arguments form the real command string
            real_command_string = " ".join(args[2:])
            set_alias(alias, real_command_string)
        else:
            print("Usage: set-alias <alias> <real_command_string>")
            log_activity("CLI command 'set-alias' missing arguments")

    elif command == 'install-path':
        script_dir = Path(__file__).resolve().parent.as_posix() # Get script directory path
        install_path(script_dir)

    elif command == 'test' and len(args) > 1 and args[1].lower() == '--signals':
         test_wireless_signals()

    elif command == 'proc':
        # Delegate process viewer commands to process_viewer module if available
        if not PROCESS_VIEWER_AVAILABLE:
            print("Error: process_viewer.py is not available. 'proc' commands are disabled.")
            log_activity("CLI command 'proc' failed: process_viewer not available.")
            return

        if len(args) < 2:
            print("Usage: proc <command> [options]")
            print("Available proc commands: list, info, tree, openfiles, connections, env, suspend, resume, priority, monitor")
            log_activity("CLI command 'proc' missing subcommand")
            return

        proc_subcommand = args[1].lower()
        proc_args = args[2:] # Arguments for the subcommand

        try:
            if proc_subcommand == 'list':
                sort_key = proc_args[0].lower() if proc_args else 'cpu'
                # Check if sorting is supported and valid
                valid_sort_keys = ['cpu', 'mem', 'name', 'pid'] # Added pid as valid key
                if sort_key not in valid_sort_keys:
                     print(f"Invalid sort key '{sort_key}'. Use {', '.join(valid_sort_keys)}.")
                     log_activity(f"CLI proc list invalid sort key: {sort_key}")
                     return
                print(f"Listing processes sorted by {sort_key}...")
                pv.list_processes(sort_key) # Assuming pv.list_processes handles sorting
                log_activity(f"CLI executed 'proc list {sort_key}'")

            elif proc_subcommand == 'info' and len(proc_args) > 0:
                pid_str = proc_args[0]
                try:
                    pid = int(pid_str)
                    pv.process_info(pid)
                    log_activity(f"CLI executed 'proc info {pid}'")
                except ValueError:
                    print("Invalid PID. Please provide a number.")
                    log_activity(f"CLI proc info invalid PID: {pid_str}")
                except psutil.NoSuchProcess:
                    print(f"No process found with PID: {pid_str}")
                    log_activity(f"CLI proc info process not found: {pid_str}")
                except psutil.AccessDenied:
                     print(f"Access denied to get info for PID {pid_str}. Try running as administrator.")
                     log_activity(f"CLI proc info access denied: {pid_str}")
                except Exception as e:
                    print(f"Error getting process info for PID {pid_str}: {e}")
                    log_activity(f"CLI proc info error for {pid_str}: {e}")

            elif proc_subcommand == 'tree':
                pv.process_tree()
                log_activity("CLI executed 'proc tree'")

            elif proc_subcommand == 'openfiles' and len(proc_args) > 0:
                 pid_str = proc_args[0]
                 try:
                     pid = int(pid_str)
                     pv.open_files(pid)
                     log_activity(f"CLI executed 'proc openfiles {pid}'")
                 except ValueError:
                     print("Invalid PID. Please provide a number.")
                     log_activity(f"CLI proc openfiles invalid PID: {pid_str}")
                 except psutil.NoSuchProcess:
                    print(f"No process found with PID: {pid_str}")
                    log_activity(f"CLI proc openfiles process not found: {pid_str}")
                 except psutil.AccessDenied:
                     print(f"Access denied to list open files for PID {pid_str}. Try running as administrator.")
                     log_activity(f"CLI proc openfiles access denied: {pid_str}")
                 except Exception as e:
                    print(f"Error listing open files for PID {pid_str}: {e}")
                    log_activity(f"CLI proc openfiles error for {pid_str}: {e}")


            elif proc_subcommand == 'connections' and len(proc_args) > 0:
                 pid_str = proc_args[0]
                 try:
                     pid = int(pid_str)
                     # Note: The process_viewer.py function might just print.
                     # If the GUI needs structured data, it uses psutil directly.
                     pv.net_connections(pid)
                     log_activity(f"CLI executed 'proc connections {pid}'")
                 except ValueError:
                     print("Invalid PID. Please provide a number.")
                     log_activity(f"CLI proc connections invalid PID: {pid_str}")
                 except psutil.NoSuchProcess:
                    print(f"No process found with PID: {pid_str}")
                    log_activity(f"CLI proc connections process not found: {pid_str}")
                 except psutil.AccessDenied:
                     print(f"Access denied to list connections for PID {pid_str}. Try running as administrator.")
                     log_activity(f"CLI proc connections access denied: {pid_str}")
                 except Exception as e:
                    print(f"Error listing connections for PID {pid_str}: {e}")
                    log_activity(f"CLI proc connections error for {pid_str}: {e}")

            elif proc_subcommand == 'env' and len(proc_args) > 0:
                 pid_str = proc_args[0]
                 try:
                     pid = int(pid_str)
                     pv.env_vars(pid)
                     log_activity(f"CLI executed 'proc env {pid}'")
                 except ValueError:
                     print("Invalid PID. Please provide a number.")
                     log_activity(f"CLI proc env invalid PID: {pid_str}")
                 except psutil.NoSuchProcess:
                    print(f"No process found with PID: {pid_str}")
                    log_activity(f"CLI proc env process not found: {pid_str}")
                 except psutil.AccessDenied:
                     print(f"Access denied to get environment variables for PID {pid_str}. Try running as administrator.")
                     log_activity(f"CLI proc env access denied: {pid_str}")
                 except Exception as e:
                    print(f"Error getting environment variables for PID {pid_str}: {e}")
                    log_activity(f"CLI proc env error for {pid_str}: {e}")

            elif proc_subcommand == 'suspend' and len(proc_args) > 0:
                 pid_str = proc_args[0]
                 try:
                     pid = int(pid_str)
                     pv.suspend_process(pid)
                     log_activity(f"CLI executed 'proc suspend {pid}'")
                 except ValueError:
                     print("Invalid PID. Please provide a number.")
                     log_activity(f"CLI proc suspend invalid PID: {pid_str}")
                 except psutil.NoSuchProcess:
                    print(f"No process found with PID: {pid_str}")
                    log_activity(f"CLI proc suspend process not found: {pid_str}")
                 except psutil.AccessDenied:
                     print(f"Access denied to suspend PID {pid_str}. Try running as administrator.")
                     log_activity(f"CLI proc suspend access denied: {pid_str}")
                 except Exception as e:
                    print(f"Error suspending PID {pid_str}: {e}")
                    log_activity(f"CLI proc suspend error for {pid_str}: {e}")


            elif proc_subcommand == 'resume' and len(proc_args) > 0:
                 pid_str = proc_args[0]
                 try:
                     pid = int(pid_str)
                     pv.resume_process(pid)
                     log_activity(f"CLI executed 'proc resume {pid}'")
                 except ValueError:
                     print("Invalid PID. Please provide a number.")
                     log_activity(f"CLI proc resume invalid PID: {pid_str}")
                 except psutil.NoSuchProcess:
                    print(f"No process found with PID: {pid_str}")
                    log_activity(f"CLI proc resume process not found: {pid_str}")
                 except psutil.AccessDenied:
                     print(f"Access denied to resume PID {pid_str}. Try running as administrator.")
                     log_activity(f"CLI proc resume access denied: {pid_str}")
                 except Exception as e:
                    print(f"Error resuming PID {pid_str}: {e}")
                    log_activity(f"CLI proc resume error for {pid_str}: {e}")

            elif proc_subcommand == 'priority' and len(proc_args) > 1:
                 pid_str = proc_args[0]
                 level = proc_args[1].lower()
                 try:
                     pid = int(pid_str)
                     pv.set_priority(pid, level)
                     log_activity(f"CLI executed 'proc priority {pid} {level}'")
                 except ValueError:
                     print("Invalid PID. Please provide a number.")
                     log_activity(f"CLI proc priority invalid PID: {pid_str}")
                 except psutil.NoSuchProcess:
                    print(f"No process found with PID: {pid_str}")
                    log_activity(f"CLI proc priority process not found: {pid_str}")
                 except psutil.AccessDenied:
                     print(f"Access denied to set priority for PID {pid_str}. Try running as administrator.")
                     log_activity(f"CLI proc priority access denied: {pid_str}")
                 except ValueError as e: # Catch invalid level from pv.set_priority
                     print(f"Invalid priority level '{level}': {e}")
                     log_activity(f"CLI proc priority invalid level {level} for {pid_str}")
                 except Exception as e:
                    print(f"Error setting priority for PID {pid_str}: {e}")
                    log_activity(f"CLI proc priority error for {pid_str}: {e}")

            elif proc_subcommand == 'monitor':
                 pv.system_monitor()
                 log_activity("CLI executed 'proc monitor'")

            else:
                print(f"❓ Unknown 'proc' command: {proc_subcommand}")
                print("Available proc commands: list, info, tree, openfiles, connections, env, suspend, resume, priority, monitor")
                log_activity(f"CLI unknown proc subcommand: {proc_subcommand}")

        except Exception as e:
             # Catch unexpected errors during proc handling
            print(f"An unexpected error occurred during 'proc' command execution: {e}")
            log_activity(f"CLI proc command unexpected error: {e}")


    # Check if the command is one of the network commands (nr alias expected)
    # Assumes 'nr' is the intended alias or it's used directly like '-f dns'
    # If the first arg doesn't match built-ins and isn't an alias, treat it as a potential net command
    # or an error. Let's explicitly check if it looks like the start of a net command.
    elif args[0].startswith('-') or (len(args) > 1 and args[1].lower() in ('dns', 'ip', 'firewall', 'netsh', 'address', 'winsock', 'tcp', 'proxy')):
        # Assuming this might be a network command like 'nr -f dns' where 'nr' was aliased away
        # Or just '-f dns' if the script was called differently.
        # Pass all args to handle_net_commands
        handle_net_commands(args)

    # Original code included '--task', 'monitor', 'netstat', 'info', 'kill', 'restart' as separate CLI commands
    # which seemed to map to pv functions. This is redundant with 'proc'.
    # The GUI ProcessViewerPanel uses pv functions directly.
    # For CLI clarity and avoiding redundancy with 'proc', these standalone pv commands should perhaps be removed or clearly marked as deprecated.
    # Let's keep them for compatibility but recommend 'proc'.
    elif command == '--task':
        if PROCESS_VIEWER_AVAILABLE:
             print("""
Process Task Options:
1. monitor       | Real-time CPU/RAM usage (use 'proc monitor')
2. netstat       | Show active connections (use 'proc connections <PID>' or system 'netstat -ano')
3. info <PID>    | Show details of a process (use 'proc info <PID>')
4. kill <PID>    | Kill process (use '--kill <PID>')
5. restart <PID> | Restart process (not implemented in pv/nr CLI)

Please use the 'proc' command instead for process management.
""")
             cmd = input("Enter command: ").strip()
             parts = cmd.split()
             # Map old --task commands to new 'proc' or other commands if possible
             if not parts:
                  print("No command entered.")
                  return
             task_cmd = parts[0].lower()
             if task_cmd == 'monitor':
                  print("Use 'proc monitor' instead.")
                  # pv.show_monitor() # Assuming pv.show_monitor exists and works
             elif task_cmd == 'netstat':
                  print("Use 'proc connections <PID>' or 'netstat -ano' directly.")
                  # pv.list_netstat() # Assuming pv.list_netstat exists and works
             elif task_cmd == 'info' and len(parts) == 2:
                  print(f"Use 'proc info {parts[1]}' instead.")
                  # try: pv.show_info(parts[1])
                  # except Exception as e: print(f"Error: {e}")
             elif task_cmd == 'kill' and len(parts) == 2:
                  print(f"Use '--kill {parts[1]}' instead.")
                  # try: pv.kill_process(parts[1]) # Assuming pv.kill_process exists and works
                  # except Exception as e: print(f"Error: {e}")
             elif task_cmd == 'restart' and len(parts) == 2:
                  print("Restart functionality is not implemented.")
             else:
                 print("❓ Invalid --task command.")
             log_activity(f"Used deprecated '--task' command: {cmd}")

        else:
            print("Error: process_viewer.py is not available. '--task' commands are disabled.")
            log_activity("CLI command '--task' failed: process_viewer not available.")


    # These standalone commands seem like leftover examples and overlap with 'proc' or main commands.
    # They are not explicitly used by the GUI, so keeping them might just add confusion.
    # Removing them for clarity, but listing them here as previously existing.
    # elif command == 'monitor': # overlaps with 'proc monitor' and 'monitor --live'
    #     print("Use 'proc monitor' for system monitor or 'monitor --live' for bandwidth.")
    #     # pv.show_monitor() if PROCESS_VIEWER_AVAILABLE else print("process_viewer not available.")
    # elif command == 'netstat': # overlaps with 'proc connections' and system 'netstat'
    #     print("Use 'proc connections <PID>' or the system 'netstat -ano' command.")
    #     # pv.list_netstat() if PROCESS_VIEWER_AVAILABLE else print("process_viewer not available.")
    # elif command == 'info' and len(args) > 1: # overlaps with 'proc info'
    #      print("Use 'proc info <PID>'.")
    #      # try: pv.show_info(args[1]) if PROCESS_VIEWER_AVAILABLE else print("process_viewer not available.")
    #      # except Exception as e: print(f"Error: {e}")
    # elif command == 'kill' and len(args) > 1: # overlaps with main '--kill'
    #      print("Use '--kill <name|pid>'.")
    #      # try: pv.kill_process(args[1]) if PROCESS_VIEWER_AVAILABLE else print("process_viewer not available.")
    #      # except Exception as e: print(f"Error: {e}")
    # elif command == 'restart' and len(args) > 1: # Not implemented in pv/nr
    #      print("Restart process functionality is not implemented.")


    # If command wasn't recognized by any specific handler
    else:
        print(f"Unknown command '{args[0]}', sweetheart! Use --help for options.")
        log_activity(f"Unknown command received: {' '.join(args)}")


# Entry point for the CLI script
if __name__ == "__main__":
    # When run directly, the script takes args from sys.argv
    # If the GUI calls nr.main(), it modifies sys.argv before calling
    main()
