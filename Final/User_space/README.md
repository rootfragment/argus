# Argus User-Space Components

This directory contains the user-space components for the Argus Linux Rootkit Detection Framework. These Python scripts are responsible for interacting with the Argus kernel modules, performing scans, analyzing results, and handling alerting.

## Components

1.  **`argus_cli.py`**: The main command-line interface and scanning engine.
2.  **`argus_alert_receiver.py`**: A dedicated UDP server for receiving and logging alerts.

---

## `argus_cli.py` - The Scanning Engine

This is the primary tool for interacting with the Argus framework. It reads data exposed by the kernel modules and compares it against the output of standard user-space utilities to find discrepancies that could indicate rootkit activity.

### Features

*   **Multiple Scan Types:**
    *   **Process Scan:** Compares the process list from the kernel's point of view with the output of `ps` to find hidden processes.
    *   **Module Scan:** Compares the loaded kernel modules from the kernel's list with the output of `lsmod` to find hidden modules (a strong indicator of a Loadable Kernel Module rootkit).
    *   **Port Scan:** Compares listening network ports seen by the kernel with the output of `ss` to find hidden backdoors.
*   **Interactive Menu:** A user-friendly menu for running scans manually.
*   **Daemon Mode:** Can run as a background daemon to perform continuous, automated scans at a regular interval (`-t <seconds>`). When anomalies are found in this mode, it automatically sends a UDP alert.
*   **UDP Alerting:** Can send alerts over UDP to a configured receiver. This is handled automatically in daemon mode and can be toggled on or off in interactive mode.
*   **Configuration:** Uses a `config.json` file to manage the list of alert receivers.

### Usage

**Prerequisites:** The Argus kernel modules must be loaded for this script to function correctly. Requires root privileges.

**Interactive Mode:**
```bash
sudo python3 argus_cli.py
```
This will display a menu where you can choose which scan to run.

**Daemon Mode:**
To run a full scan every 60 seconds and send alerts on findings:
```bash
sudo python3 argus_cli.py -t 60
```

**Stopping the Daemon:**
```bash
sudo python3 argus_cli.py --stop
```

---

## `argus_alert_receiver.py` - The Alert Receiver

This script is a lightweight UDP server designed to listen for and log alert messages sent by `argus_cli.py`. It acts as a centralized collection point for security alerts from one or more monitored systems.

### Features

*   **Centralized Logging:** Collects alerts from any number of Argus clients into a single `argus_alerts.log` file.
*   **Rate Limiting:** Prevents log flooding by limiting the number of alerts it will process from a single IP address (by default, 1 alert per 10 seconds).
*   **Daemon Mode:** Can run as a persistent background service using the `--daemon` flag.
*   **Remote Stop:** Can be cleanly stopped from the command line using the `--stop` flag.

### Usage

**Foreground Mode:**
```bash
python3 argus_alert_receiver.py
```
The receiver will run in the current terminal. Press `Ctrl+C` to stop it.

**Daemon Mode:**
To run the receiver as a background service:
```bash
python3 argus_alert_receiver.py --daemon
```

**Stopping the Daemon:**
```bash
python3 argus_alert_receiver.py --stop
```

---

## How They Work Together

1.  The **`argus_alert_receiver.py`** is started (ideally as a daemon) on a machine designated for monitoring.
2.  On the systems being monitored, the **`argus_cli.py`** script is run (either in interactive or daemon mode).
3.  The `config.json` file for `argus_cli.py` is configured with the IP address and port of the machine running the `argus_alert_receiver.py`.
4.  When `argus_cli.py` performs a scan and finds a potential threat, it sends a UDP packet containing the details of the finding to the receiver.
5.  The `argus_alert_receiver.py` receives this packet and logs the alert to `argus_alerts.log`, timestamped and with the source IP of the reporting client.
