import psutil
import platform
import time
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich import box
from rich.tree import Tree

console = Console()

def system_monitor():
    console.rule("[bold red]System Monitor")
    cpu = psutil.cpu_percent(interval=1, percpu=True)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    uptime = time.time() - psutil.boot_time()

    console.print(f"[bold cyan]Uptime:[/] {uptime:.0f} sec")
    console.print(f"[bold green]CPU (per core):[/] {cpu}")
    console.print(f"[bold magenta]RAM:[/] {ram.percent}% used")
    console.print(f"[bold yellow]Disk:[/] {disk.percent}% used")

def list_processes(sort_by='cpu'):
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads', 'status', 'create_time']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    key_map = {
        'cpu': lambda p: p['cpu_percent'],
        'mem': lambda p: p['memory_percent'],
        'name': lambda p: p['name'].lower()
    }

    processes.sort(key=key_map.get(sort_by, 'cpu'), reverse=True)

    table = Table(title="Process List", box=box.SQUARE)
    table.add_column("PID")
    table.add_column("Name")
    table.add_column("CPU%")
    table.add_column("MEM%")
    table.add_column("Threads")
    table.add_column("Status")
    table.add_column("Started")

    for p in processes[:30]:
        started = datetime.fromtimestamp(p['create_time']).strftime('%H:%M:%S') if 'create_time' in p else '?'
        table.add_row(
            str(p['pid']),
            str(p['name']),
            f"{p['cpu_percent']:.1f}",
            f"{p['memory_percent']:.1f}",
            str(p['num_threads']),
            str(p['status']),
            started
        )

    console.print(table)

def process_info(pid):
    try:
        proc = psutil.Process(int(pid))
        with proc.oneshot():
            info = {
                'name': proc.name(),
                'status': proc.status(),
                'username': proc.username(),
                'cpu_percent': proc.cpu_percent(interval=0.2),
                'memory_percent': proc.memory_percent(),
                'threads': proc.num_threads(),
                'handles': proc.num_handles() if hasattr(proc, 'num_handles') else '-',
                'create_time': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'cmdline': ' '.join(proc.cmdline()),
                'ppid': proc.ppid()
            }

        console.rule(f"[bold green]Process Info: {info['name']} ({pid})")
        for k, v in info.items():
            console.print(f"[bold]{k}:[/] {v}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")

def process_tree():
    console.rule("[bold blue]Process Tree")
    root = Tree("Processes")
    pid_map = {}

    for proc in psutil.process_iter(['pid', 'name', 'ppid']):
        pid_map[proc.info['pid']] = proc.info

    added = set()

    def add_branch(parent, pid):
        if pid in added:
            return
        proc = pid_map.get(pid)
        if not proc:
            return
        entry = f"[cyan]{proc['pid']}[/] [bold]{proc['name']}[/]"
        node = parent.add(entry)
        added.add(pid)
        for child in [p['pid'] for p in pid_map.values() if p['ppid'] == pid]:
            add_branch(node, child)

    for p in pid_map.values():
        if p['ppid'] == 0:
            add_branch(root, p['pid'])

    console.print(root)

def open_files(pid):
    try:
        proc = psutil.Process(int(pid))
        files = proc.open_files()
        console.rule(f"[bold]Open Files - PID {pid}")
        for f in files:
            console.print(f.path)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")

def net_connections(pid):
    try:
        proc = psutil.Process(int(pid))
        conns = proc.connections(kind='inet')
        table = Table(title=f"Connections for PID {pid}", box=box.SIMPLE)
        table.add_column("Type")
        table.add_column("Local")
        table.add_column("Remote")
        table.add_column("Status")
        for c in conns:
            table.add_row(
                str(c.type),
                f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-",
                f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-",
                c.status
            )
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")

def env_vars(pid):
    try:
        proc = psutil.Process(int(pid))
        env = proc.environ()
        console.rule(f"[bold]Environment Variables - PID {pid}")
        for k, v in env.items():
            console.print(f"[green]{k}[/]: {v}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")

def suspend_process(pid):
    try:
        psutil.Process(int(pid)).suspend()
        console.print(f"[yellow]Process {pid} suspended[/]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")

def resume_process(pid):
    try:
        psutil.Process(int(pid)).resume()
        console.print(f"[green]Process {pid} resumed[/]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")

def set_priority(pid, level):
    try:
        proc = psutil.Process(int(pid))
        levels = {
            'low': psutil.IDLE_PRIORITY_CLASS,
            'below': psutil.BELOW_NORMAL_PRIORITY_CLASS,
            'normal': psutil.NORMAL_PRIORITY_CLASS,
            'above': psutil.ABOVE_NORMAL_PRIORITY_CLASS,
            'high': psutil.HIGH_PRIORITY_CLASS,
            'realtime': psutil.REALTIME_PRIORITY_CLASS
        }
        proc.nice(levels.get(level, psutil.NORMAL_PRIORITY_CLASS))
        console.print(f"[cyan]Priority set to {level}[/]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
