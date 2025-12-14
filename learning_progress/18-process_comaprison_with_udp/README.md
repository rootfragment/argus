# Overview
Compares process from user-space and kernel-space checks for anomalies from both the lists and then sends a UDP alert, the destination of the program can be set by manipulating the config fields. Alerts are intended to be sent to a n/w admin to alert the detection of a suspicious process.

## How It Works

The core of this detector lies in its two-pronged approach to process discovery:

1.  **Kernel-Level View:** A custom Linux kernel module (`kernel_space_view.c`) is used to create a file in the `/proc` filesystem at `/proc/p1`. When read, this file provides a direct, unfiltered list of all running processes straight from the kernel's own process list (`task_struct`). This is considered the "ground truth."

2.  **Userspace-Level View:** The standard `ps` command is used to list the running processes from a userspace perspective. This is the view that a normal user or administrator would see.

The `monitor.py` script continuously compares these two lists. If a process exists in the kernel's list but is missing from the `ps` output, it is flagged as a "hidden process," and an alert is triggered.

## Key Features

- **Anomaly Detection:** Identifies processes that may be hidden from standard userspace tools.
- **Continuous Monitoring:** Runs in a loop to check for anomalies every 2 seconds.
- **UDP Alerts:** Immediately sends a UDP packet with details of the anomaly to a configurable IP address and port.
- **Simple & Extensible:** Built with a minimal set of components, making it easy to understand and modify.


### Load the Kernel Module

Load the module into the kernel using the `insmod` command. This requires root privileges.

```bash
sudo insmod kernel_space_view.ko
```

This will create the `/proc/p1` file that the monitoring script needs.

### Run the Monitor

Execute the Python script to start monitoring for hidden processes:

```bash
python3 monitor.py
```

The script will now run continuously, checking for anomalies every 2 seconds.

## The UDP Alerting System

A critical feature of this program is its ability to send immediate alerts when an anomaly is detected.

When the `monitor.py` script finds a discrepancy between the kernel and userspace process lists, it constructs a detailed message and sends it as a **UDP packet**. This method is lightweight and fast, making it ideal for real-time notifications.

### Alert Configuration

The destination for these alerts can be configured at the top of the `monitor.py` script:

```python
# --- CONFIGURATION ---
ALERT_IP = "127.0.0.1"  # The IP to send alerts to
ALERT_PORT = 12345      # The port to send alerts to
# ...
```

By default, alerts are sent to `127.0.0.1` (localhost), meaning they are sent to the same machine the script is running on. You can change this to any IP address to send alerts to a remote machine, such as a central logging server.

### How to Receive the Alerts

You can easily listen for these UDP alerts using a simple utility like `netcat` (`nc`).

1.  **Open a new terminal.**
2.  Run the following command to listen for UDP packets on the configured port:

    ```bash
    nc -ul -p 12345
    ```

When the monitor detects an anomaly, the details of the hidden process will instantly appear in this `netcat` terminal. This provides a simple and effective way to get real-time notifications of potential security issues on your system.
