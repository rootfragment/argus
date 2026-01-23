#!/usr/bin/env python3
import subprocess
import re
import os
import sys
import socket
import json
def display_banner():
    banner = r"""
          ___      .______        _______  __    __       _______.
         /   \     |   _  \      /  _____||  |  |  |     /       |
        /  ^  \    |  |_)  |    |  |  __  |  |  |  |    |   (----`
       /  /_\  \   |      /     |  | |_ | |  |  |  |     \   \    
      /  _____  \  |  |\  \----.|  |__| | |  `--'  | .----)   |   
     /__/     \__\ | _| `._____| \______|  \______/  |_______/    
                                                                  
                                          
    -- Linux Rootkit Detection Framework --
    """
    print(banner)
    
    
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
	"listener_list":[
		{
		"ip" : "127.0.0.1",
		"port" : 12345,
		"enabled" : True,
		}
	]
}
def create_config():
	is_sudo = os.getuid() == 0 and 'SUDO_UID' in os.environ
	try:
		if is_sudo:
			orginal_uid = int(os.environ['SUDO_UID'])
			orginal_gid = int(os.environ['SUDO_GID'])
			root_euid = os.geteuid()
			root_egid = os.getegid()
			
			try:
				os.setegid(orginal_gid)
				os.seteuid(orginal_uid)
				with open(CONFIG_FILE , "w") as f:
					json.dump(DEFAULT_CONFIG, f, indent=4)
			except OSError as e:
				print(f"[!] Error : Could not create config file for the user {orginal_uid} : {e}")
			finally:
				os.seteuid(root_euid)
				os.setegid(root_egid)
		else:
			with open(CONFIG_FILE, "w") as f:	
				json.dump(DEFAULT_CONFIG, f, indent=4)
		print("[*] Created a sample config file since no configuration file was found. Edit the file and rerun the program")
	except OSError as e:
		print(f,"[x] Error : Could not create config file : {e}")
	except KeyError:
		print("[x] Error : SUDO_UID or SUDO_GID not found in environment. Cannot determine the user.")
	sys.exit(0)
		
	
def load_config():
    if not os.path.exists(CONFIG_FILE):
        create_config()
    with open(CONFIG_FILE,"r") as f:
        return json.load(f)
        
        
def send_udp_alert(findings, config):
    if not findings:
        return
    message = "\n".join(findings)
    sent_count = 0
    for listener in config.get("listener_list", []):
        if not listener.get("enabled", False):
            continue
        ip = listener["ip"]
        port = listener["port"]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(message.encode('utf-8'), (ip, port))
            sent_count += 1
        except Exception as e:
            print(f"[!] UDP send failed ({ip}:{port}): {e}")
    if sent_count > 0:
        print(f"[+] UDP alert sent to {sent_count} listener(s).")
        
        
def get_ps_processes():
    try:
        ps_output = subprocess.check_output(["ps", "-e", "-o", "pid=,comm="]).decode()
        ps_dict = {}
        for line in ps_output.strip().splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2:
                pid, cmd = parts
                ps_dict[pid.strip()] = cmd.strip()
        return ps_dict
    except FileNotFoundError:
        print("[!] 'ps' command not found. Is this a standard Linux environment?")
        return {}
    except Exception as e:
        print(f"[x] Error running 'ps': {e}")
        return {}
        
        
def get_kernel_processes(proc_file="/proc/rk_ps"):
    ker_dict = {}
    try:
        with open(proc_file, "r") as f:
            for line in f:
                parts = line.strip().split(maxsplit=1)
                if not parts:
                    continue
                pid = parts[0]
                cmd = parts[1] if len(parts) > 1 else "?"
                ker_dict[pid] = cmd
        return ker_dict
    except FileNotFoundError:
        print(f"[!] Kernel proc file '{proc_file}' not found. Is the kernel module loaded?")
        return None
    except Exception as e:
        print(f"[x] Error reading {proc_file}: {e}")
        return None
        
        
def run_process_scan():
    print("\n" + "="*20)
    print("  Running Process Scan")
    print("="*20)
    ps_process = get_ps_processes()
    kern_process = get_kernel_processes()
    if kern_process is None:
        return []
    missing_ps = set(kern_process.keys()) - set(ps_process.keys())
    findings = []
    if missing_ps:
        print("\n[!] Processes found by kernel but hidden from 'ps' (potential rootkit activity):")
        for pid in sorted(missing_ps, key=int):
            finding = f"Hidden Process: PID {pid:<6} {kern_process[pid]}"
            print(f"  -> {finding}")
            findings.append(finding)
    else:
        print("\n[+] No processes appear to be hidden from 'ps'.")
    print("\n" + "="*25)
    print("  Process Scan Complete")
    print("="*25)
    return findings
    
    
def get_user_modules(proc_file="/proc/modules"):
    user_view = set()
    try:
        with open(proc_file) as f:
            for line in f:
                if not line.strip():
                    continue
                mod_name = line.split()[0]
                user_view.add(mod_name)
        return user_view
    except FileNotFoundError:
        print(f"[!] Could not open '{proc_file}'.")
        return None
    except Exception as e:
        print(f"[x] Error reading {proc_file}: {e}")
        return None
        
        
def get_kernel_modules(proc_file="/proc/rk_mods"):
    kern_view = set()
    try:
        with open(proc_file) as f:
            for line in f:
                if not line.strip():
                    continue
                mod_name = line.split()[0]
                kern_view.add(mod_name)
        return kern_view
    except FileNotFoundError:
        print(f"[!] Kernel proc file '{proc_file}' not found. Is the kernel module loaded?")
        return None
    except Exception as e:
        print(f"[x] Error reading {proc_file}: {e}")
        return None
        
        
def run_module_scan():
    print("\n" + "="*25)
    print("  Running Module Scan")
    print("="*25)
    user_view = get_user_modules()
    kern_view = get_kernel_modules()
    if user_view is None or kern_view is None:
        return []
    hidden_mods = kern_view - user_view
    findings = []
    if hidden_mods:
        print("\n[!] Kernel modules hidden from 'lsmod' (strong indicator of LKM rootkit):")
        for mod in sorted(hidden_mods):
            finding = f"Hidden Module: {mod}"
            print(f"  -> {finding}")
            findings.append(finding)
    else:
        print("\n[+] No hidden kernel modules detected.")
    print("\n" + "="*25)
    print("  Module Scan Complete")
    print("="*25)
    return findings
    
    
def get_kernel_ports(proc_file="/proc/rk_sockets"):
    kernel_ports = set()
    port_map = {}
    try:
        with open(proc_file, "r") as f:
            data = f.read()
            entries = re.findall(r"pid=(\d+)\s+comm=([\w\-\.\/]+)\s+source port=(\d+)", data)
            for pid, comm, port in entries:
                port_num = int(port)
                kernel_ports.add(port_num)
                port_map[port_num] = (pid, comm)
    except FileNotFoundError:
        print(f"[!] Kernel proc file '{proc_file}' not found. Is the kernel module loaded?")
        return None, {}
    except Exception as e:
        print(f"[x] Error reading {proc_file}: {e}")
        return None, {}
    return kernel_ports, port_map
    
    
def get_userspace_ports():
    userspace_ports = set()
    try:
        result = subprocess.run(["ss", "-ltunp"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ports = re.findall(r":(\d+)\s", result.stdout)
        for p in ports:
            userspace_ports.add(int(p))
    except FileNotFoundError:
        print("[!] 'ss' command not found. Is this a standard Linux environment?")
        return set()
    except Exception as e:
        print(f"[x] Error fetching userspace ports with 'ss': {e}")
        return set()
    return userspace_ports
    
    
def run_port_scan():
    print("\n" + "="*25)
    print("  Running Port Scan")
    print("="*25)
    kernel_ports, port_map = get_kernel_ports()
    userspace_ports = get_userspace_ports()
    if kernel_ports is None:
        return []
    hidden_from_userspace = kernel_ports - userspace_ports
    findings = []
    if hidden_from_userspace:
        print("\n[!] Listening ports found by kernel but hidden from 'ss' (potential backdoor):")
        for port in sorted(hidden_from_userspace):
            pid, comm = port_map.get(port, ("?", "?"))
            finding = f"Hidden Port: {port} held by '{comm}' (PID {pid})"
            print(f"    -> {finding}")
            findings.append(finding)
    else:
        print("\n[+] No hidden listening ports detected.")
    print("\n" + "="*25)
    print("  Port Scan Complete")
    print("="*25)
    return findings
    
    
def analyze_findings(all_findings):
    print("\n" + "#"*25)
    print("  Full Scan Analysis")
    print("#"*25)
    if not all_findings:
        print("\n[***] System appears clean. No anomalies detected across all scans.")
        return
    has_hidden_procs = any("Hidden Process" in f for f in all_findings)
    has_hidden_mods = any("Hidden Module" in f for f in all_findings)
    has_hidden_ports = any("Hidden Port" in f for f in all_findings)
    print("\n[!] Potential threats detected. Summary based on findings:")
    if has_hidden_procs and not has_hidden_mods:
        print("""
    - Type: Process-Hiding Rootkit
    - Details: The malware is actively hiding its processes from standard tools like 'ps'.
      This is common for user-land rootkits that modify /proc or intercept system calls.
""")
    if has_hidden_mods:
        print("""
    - Type: Kernel-Level Rootkit (LKM)
    - Details: A Loadable Kernel Module (LKM) is hiding itself from 'lsmod'. This is a
      strong indicator of a sophisticated rootkit operating with kernel privileges. It may
      also be responsible for hiding processes and ports.
""")
    if has_hidden_ports and not has_hidden_mods:
        print("""
    - Type: Hidden Backdoor / Service
    - Details: A service is listening on a port but is hiding from standard tools like 'ss'.
      This could be a standalone backdoor or part of a larger malware framework.
""")
    if has_hidden_procs and has_hidden_mods and has_hidden_ports:
        print("""
    - Type: Advanced Kernel-Level Rootkit
    - Details: The malware exhibits multiple stealth capabilities: hiding its kernel module,
      its processes, and its network listeners. This indicates a full-featured rootkit
      with deep system integration.
""")
    print("#"*25)
    
    
def run_full_scan():
    all_findings = []
    all_findings.extend(run_process_scan())
    all_findings.extend(run_module_scan())
    all_findings.extend(run_port_scan())
    analyze_findings(all_findings)
    return all_findings
    
    
def display_menu(stat):
    print("\n" + "#"*60)
    print(" "*23 +"ARGUS Scan Menu")
    print("#"*60)
    print("\n"+"[1] Compare Processes (Kernel vs /bin/ps)")
    print("[2] Compare Kernel Modules (Kernel vs /proc/modules)")
    print("[3] Compare Network Ports (Kernel vs /bin/ss)")
    print("[4] Perform Full Scan (All checks)")
    print(f"[5] Toggle udp alert (Currently : {'ON' if stat else 'OFF'})" )
    print("\n[99] Exit")
    print("-"*15)
    
    
def main():
    stat = False
    if os.geteuid() != 0:
        print("[!] Warning: This tool gives the most accurate results when run as root.")
    try:
        config = load_config()
    except Exception as e:
        print(f"[x] Critical error loading config.json: {e}")
        sys.exit(1)
    display_banner()
    while True:
        display_menu(stat)
        try:
            choice = input("Argus > ")
            if choice == '1':
                findings = run_process_scan()
                if stat and findings:
                	send_udp_alert(findings, config)
            elif choice == '2':
                findings = run_module_scan()
                if stat and findings:
                	send_udp_alert(findings, config)
            elif choice == '3':
                findings = run_port_scan()
                if stat and findings:
                	send_udp_alert(findings, config)
            elif choice == '4':
                findings = run_full_scan()
                if stat and findings:
                	send_udp_alert(findings, config)
            elif choice == '5':
                stat = not stat
                print(f"[+] UDP alerts {'ENABLED' if stat else 'DISABLED'}")
            elif choice == '99':
                print("System observation terminated." + "\n" +"ARGUS sleeps")
                break
            else:
                print(f"Unknown command: {choice}")
        except KeyboardInterrupt:
            print("\nSystem observation terminated. ARGUS sleeps.")
            break
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")
            
            
            
if __name__ == "__main__":
    main()
