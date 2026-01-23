# Argus - Userspace Detection Client

This is the userspace command-line interface (CLI) for the Argus Linux Rootkit Detection Framework. This Python script interacts with the Argus kernel module to scan for and identify discrepancies between the kernel's view of the system and the userspace's view, which can be a strong indication of rootkit activity.

## Features

- **Interactive Menu:** Provides a simple, menu-driven interface to run different security scans.
- **Process Scan:** Compares the process list from the Argus kernel module (`/proc/rk_ps`) with the output of the standard `ps` command to detect hidden processes.
- **Module Scan:** Compares the kernel module list from `/proc/rk_mods` with the list from `/proc/modules` to detect hidden LKMs.
- **Port Scan:** Compares the list of listening network ports from `/proc/rk_sockets` with the output of the `ss` command to find hidden backdoors.
- **Full Scan:** Runs all three scans sequentially for a comprehensive system check.
- **Threat Analysis:** Provides a high-level summary of the findings, suggesting the type of potential rootkit (e.g., Process-Hiding, LKM, Advanced Kernel Rootkit).
- **Configurable UDP Alerts:** Can be configured to automatically send scan results to one or more remote UDP listeners for centralized monitoring.

## How It Works

The client operates on a simple principle: **trust the kernel**. It reads the "ground truth" data from the `/proc/rk_*` files created by the Argus kernel module. It then gathers the equivalent data from standard userspace utilities (`ps`, `ss`, etc.). By finding the difference between these two sets, it can pinpoint resources that are being actively hidden from the userspace, a common technique used by rootkits.

For example, if a process PID appears in `/proc/rk_ps` but not in the output of `ps -e`, it is flagged as a "Hidden Process."

## Prerequisites

1.  **Argus Kernel Module:** The `argus_lkm.ko` module must be loaded into the kernel. This script is entirely dependent on the `/proc/rk_*` files created by the module.
2.  **Root Privileges:** The script should be run as root (`sudo`) to ensure it has the necessary permissions to read proc files and run system commands accurately.
3.  **Standard Linux Utilities:** The script relies on `ps` and `ss` being installed and available in the system's PATH.

## Usage

1.  Ensure the Argus kernel module is loaded (`sudo insmod argus_lkm.ko`).
2.  Run the client with root privileges:
    ```bash
    sudo ./argus_cli.py
    ```
3.  Use the interactive menu to select a scan:
    - `[1]` Process Scan
    - `[2]` Module Scan
    - `[3]` Port Scan
    - `[4]` Full Scan
    - `[5]` Toggle UDP alerts ON/OFF for the current session.
    - `[99]` Exit

## Configuration

The script uses a `config.json` file for configuration. If this file is not found, a default one will be created automatically.

### UDP Alerts

To receive alerts, edit the `config.json` file and add your listener details.

**Default `config.json`:**
```json
{
    "listener_list": [
        {
            "ip": "127.0.0.1",
            "port": 12345,
            "enabled": true
        }
    ]
}
```

- **`ip`**: The IP address of the machine listening for UDP packets.
- **`port`**: The port on the listening machine.
- **`enabled`**: Set to `true` to send alerts to this listener, `false` to disable.

You can add multiple listener objects to the `listener_list` array to send alerts to several destinations.
