import subprocess
import time
import socket
import os


ALERT_IP = "127.0.0.1"
ALERT_PORT = 12345
PROC_FILE_PATH = "/proc/p1"
CHECK_INTERVAL = 2  


def get_ps_process():
    try:
        ps_output = subprocess.check_output(["ps", "-e", "-o", "pid=,comm="]).decode()
        ps_dict = {}
        for line in ps_output.strip().splitlines():
            pid, cmd = line.strip().split(maxsplit=1)
            ps_dict[pid] = cmd
        return ps_dict
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[!] Error getting userspace process list: {e}")
        return None

def get_kernel_process():
    if not os.path.exists(PROC_FILE_PATH):
        return None
    
    ker_dict = {}
    try:
        with open(PROC_FILE_PATH, "r") as f:
            for line in f:
                parts = line.strip().split(maxsplit=1)
                if not parts:
                    continue
                pid = parts[0]
                cmd = parts[1] if len(parts) > 1 else "?"
                ker_dict[pid] = cmd
        return ker_dict
    except IOError as e:
        print(f"[!] Error reading kernel process list from {PROC_FILE_PATH}: {e}")
        return None

def send_udp_alert(message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(message.encode(), (ALERT_IP, ALERT_PORT))
            print(f"[*] UDP alert sent to {ALERT_IP}:{ALERT_PORT}")
    except socket.error as e:
        print(f"[!] Error sending UDP alert: {e}")

def compare_processes(ps_process, kern_process):
    if ps_process is None or kern_process is None:
        return

    missing_ps = set(kern_process.keys()) - set(ps_process.keys())
    missing_ker = set(ps_process.keys()) - set(kern_process.keys())

    anomaly_found = False
    alert_message = ""

    if missing_ps:
        anomaly_found = True
        message = "\n[!] Anomaly Detected: Processes hidden from ps:"
        print(message)
        alert_message += message + "\n"
        for pid in sorted(missing_ps, key=int):
            line = f"  PID {pid:<6} {kern_process[pid]}"
            print(line)
            alert_message += line + "\n"
    
    if missing_ker:
        anomaly_found = True
        message = "\n[!] Anomaly Detected: Processes in ps but not in kernel list:"
        print(message)
        alert_message += message + "\n"
        for pid in sorted(missing_ker, key=int):
            line = f"  PID {pid:<6} {ps_process[pid]}"
            print(line)
            alert_message += line + "\n"

    if anomaly_found:
        send_udp_alert(alert_message)
    else:
        print("[+] No anomalies detected. Process lists are consistent.")

def main():
    if not os.path.exists(PROC_FILE_PATH):
        print(f"[!] Error: Proc file '{PROC_FILE_PATH}' not found.")
        print(" [?] Is kernel module loaded ?")
        return

    print(f"[*] Monitoring for anomalies every {CHECK_INTERVAL} seconds.")
    print(f"[*] UDP alerts will be sent to {ALERT_IP}:{ALERT_PORT} on detection.")

    while True:
        ps_process = get_ps_process()
        kern_process = get_kernel_process()
        
        compare_processes(ps_process, kern_process)
        
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user.")
