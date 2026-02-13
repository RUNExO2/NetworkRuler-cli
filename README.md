# NETWORK RULER 
_A command-line network control tool for Windows power users_

**NETWORK RULER** is a lightweight Python-based CLI utility that offers fine-grained, per-process and per-service network control on Windows. Whether you're a gamer, sysadmin, or power user—this tool lets you monitor, throttle, kill, and log network activity with precision.

---

##  Features

-  List all running apps and services
-  Kill processes or stop services (by name or PID)
-  Live bandwidth monitoring
-  Save/load network profiles *(throttling coming soon)*
-  Smart alias system (`nr` global shortcut)
-  Log all network activity to custom files
-  Stealth mode for background execution

---

##  Commands Overview

| Command                             | Description                                      |
|------------------------------------|--------------------------------------------------|
| `--list`                           | List all running processes and services         |
| `app --list`                       | List only apps                                  |
| `srv --list`                       | List only services                              |
| `--kill <name|pid>`                | Kill process or stop service                    |
| `--limit <process.exe> <speed>`    | Throttle a process *(e.g., `5mb`) *             |
| `background app --limit <speed>`   | Throttle background apps *(e.g., `1mb`) *       |
| `monitor --live`                   | View real-time bandwidth stats                  |
| `save <profile> <settings>`        | Save current setup to a profile                 |
| `load <profile>`                   | Load and execute a saved profile                |
| `log <file> <activity>`            | Append logs to a custom file                    |
| `stealth`                          | Run tool hidden in background                   |
| `--help`                           | Show help/usage info                            |

>  Throttling is **not yet functional**

---

##  Process Viewer (`proc`)

```
proc list [sort_key]
proc info <PID>
proc tree
proc openfiles <PID>
proc connections <PID>
proc env <PID>
proc resume <PID>
proc priority <PID> <level>
proc monitor
```

---

##  Network Commands (`nr` aliases)

```
nr -f dns
nr -r dns
nr -d ip
nr -renew ip
nr -s config
nr -s interfaces
nr -show firewall
nr -reset firewall
nr -on firewall
nr -off firewall
nr -reset winsock
nr -reset tcp
nr -reset proxy
nr -show proxy
nr -off proxy
```

---

##  Misc Commands

```
--task
monitor
netstat
info <PID>
kill <PID>
restart <PID>
```

---

##  Examples

```
network ruler --list
network ruler --kill explorer.exe
network ruler app --list
network ruler --limit fdm.exe 5mb
network ruler background app --limit 1mb
network ruler monitor --live
nr save gaming "-f dns , -reset winsock , -off proxy"
network ruler load gaming
network ruler log net.log "Gaming profile active"
network ruler stealth
```

---

##  Alias Setup

To use `nr` globally:

1. Place `network_ruler.bat` & `network_ruler.ps1` in any folder
2. Add that folder to your system `PATH`
3. Now just run `nr` from any terminal

```
nr --list
```

---

##  Pro Tip: Best Use of Profiles

For the ultimate network and performance boost:

1. Run:
   ```
   nr --help
   nr --list
   ```
2. Copy the **entire output** of both commands.
3. Paste it into your favorite AI and say:
   ```
   Give me the best profile to enhance the network and performance of my PC
   ```
4. Apply the suggested settings using:
   ```
   nr load <AI-suggested-profile>
   ```

---

##  Notes

- Run as admin for full functionality
- Throttling support is in progress
- Profile save/load works for command replays

---

## Author

Built by **RUNEoX**
