import process_viewer as pv

def test_info():
    import os
    pv.show_info(os.getpid())

def test_netstat():
    pv.list_netstat()

def test_kill_restart():
    import subprocess
    p = subprocess.Popen(["notepad"])
    pv.kill_process(p.pid)
