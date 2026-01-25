# Argus UDP Alert Receiver

This document provides an overview of the `argus_alert_receiver.py` script, a component of the Argus Linux Rootkit Detection Framework.

## What is the Receiver?

The `argus_alert_receiver.py` script is a lightweight, standalone UDP server designed to listen for and log alert messages sent by the Argus client (`argus_cli.py`) or the Argus daemon (`argus_cli.py`).

Its primary purpose is to provide a centralized collection point for security alerts. You can run this receiver on a dedicated security monitoring machine, and configure all your monitored systems to send their Argus alerts to it.

## How It Works

The script performs the following actions:

1.  **Binds to a Socket:** It opens a UDP socket and binds it to a specified IP address and port. By default, it listens on `0.0.0.0`, meaning it will accept packets from any network interface on the host machine.
2.  **Listens for Data:** It enters an infinite loop, waiting to receive UDP packets.
3.  **Logs Alerts:** When a packet is received, the script:
    *   Decodes the message from the packet.
    *   Logs the message to a local file named `argus_alerts.log`.
    *   Each log entry is timestamped and includes the IP address of the system that sent the alert, making it easy to trace the source of a detection.

## How to Use

The receiver can be run with default settings or with custom command-line arguments.

### Running with Defaults

To start the receiver and have it listen on all network interfaces (`0.0.0.0`) on the default port (`12345`), simply run:

```bash
python3 argus_alert_receiver.py
```

The script will print a confirmation that it has started and will continue running in the foreground.

### Specifying Host and Port

You can use the `--host` and `--port` arguments to change the listening address and port.

**Example:** To listen only on the local loopback interface on port `5000`:

```bash
python3 argus_alert_receiver.py --host 127.0.0.1 --port 5000
```

### Stopping the Receiver

To stop the script, press `Ctrl+C` in the terminal where it is running.

## Logging

### The Alert Log File

*   **File Name:** `argus_alerts.log`
*   **Location:** The file is created in the same directory from which you run the `argus_alert_receiver.py` script.

### Log Format

Each line in the log file is formatted for clarity and easy parsing:

`YYYY-MM-DD HH:MM:SS,ms - [ALERT FROM SENDER_IP] - Message`

**Example Log Entries:**
```
2026-01-24 15:00:00,123 - [ALERT FROM 192.168.1.101] - [WARNING] - Detection: Hidden Process: PID 12345  evil_process
2026-01-24 15:05:00,456 - [ALERT FROM 10.0.0.55] - [INFO] - Full scan complete. 0 anomalies found.
```
