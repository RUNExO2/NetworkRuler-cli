from logs import log_action, log_event, log_error, log_exception, log_debug, log_method_entry, log_method_exit
import process_viewer as pv

def test_info():
log_method_entry("test_info")
    import os
    pv.show_info(os.getpid())

log_method_exit("test_info")
def test_netstat():
log_method_entry("test_netstat")
    pv.list_netstat()

log_method_exit("test_netstat")
def test_kill_restart():
log_method_entry("test_kill_restart")
    import subprocess
    p = subprocess.Popen(["notepad"])
    pv.kill_process(p.pid)
log_method_exit("test_kill_restart")
