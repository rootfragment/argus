import subprocess
import re

def get_kernel_port(proc_file="/proc/open_ports"):
    kernel_ports = set()
    port_map = {}
    try:
        with open(proc_file, "r") as f:
            data = f.read()
            entries = re.findall(r"pid=(\d+)\s+comm=([\w\-\.]+)\s+source port=(\d+)", data)
            for pid, comm, port in entries:
                port_num = int(port)
                kernel_ports.add(port_num)
                port_map[port_num] = (pid, comm)
    except Exception as e:
        print(f"[!] Error reading {proc_file}: {e}")
    return kernel_ports, port_map


def get_userspace_ports():
    userspace_ports = set()
    try:
        result = subprocess.run(["ss", "-tanup"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ports = re.findall(r":(\d+)\s", result.stdout)
        for p in ports:
            userspace_ports.add(int(p))
    except Exception as e:
        print(f"[!] Error fetching userspace ports: {e}")
    return userspace_ports


kernel_ports, port_map = get_kernel_port()
userspace_ports = get_userspace_ports()
hidden_from_userspace = kernel_ports - userspace_ports

if hidden_from_userspace:
    print("[!] Hidden ports detected:\n")
    for port in sorted(hidden_from_userspace):
        pid, comm = port_map.get(port, ("?", "?"))
        print(f"    → Port {port} held by {comm} with PID {pid}")
else:
    print("[✓] No hidden ports detected.")
