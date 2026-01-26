# Argus UDP Alert Receiver

This document provides an overview of the `argus_alert_receiver.py` script, a component of the Argus Linux Rootkit Detection Framework.

## What is the Receiver?

The `argus_alert_receiver.py` script is a lightweight, standalone UDP server designed to listen for and log alert messages sent by the Argus client (`argus_cli.py`) or the Argus daemon (`argus_cli.py`).

Its primary purpose is to provide a centralized collection point for security alerts. You can run this receiver on a dedicated security monitoring machine, and configure all your monitored systems to send their Argus alerts to it.

## Features

The receiver includes several features to enhance its usability and prevent log flooding:

*   **Rate Limiting:** To prevent a single, compromised machine from overwhelming the log file, the receiver implements a simple per-IP rate limit. By default, it will only log one alert every 10 seconds from the same IP address. Subsequent alerts within this window are suppressed.
*   **Daemon Mode:** The receiver can be run as a background daemon process. This "fire and forget" mechanism allows the receiver to run continuously without requiring an active terminal session.
*   **Remote Stop:** When running in daemon mode, the receiver can be cleanly shut down using the `--stop` command, which terminates the background process.

## How It Works

The script performs the following actions:

1.  **Binds to a Socket:** It opens a UDP socket and binds it to a specified IP address and port. By default, it listens on `0.0.0.0`, meaning it will accept packets from any network interface on the host machine.
2.  **Listens for Data:** It enters an infinite loop, waiting to receive UDP packets.
3.  **Logs Alerts:** When a packet is received, the script:
    *   Checks if the sender's IP is rate-limited.
    *   Decodes the message from the packet.
    *   Logs the message to a local file named `argus_alerts.log`.
    *   Each log entry is timestamped and includes the IP address of the system that sent the alert, making it easy to trace the source of a detection.

## How to Use

The receiver can be run in the foreground for interactive use or as a background daemon for continuous monitoring.

### Running in the Foreground

To start the receiver and have it listen on all network interfaces (`0.0.0.0`) on the default port (`12345`), simply run:

```bash
python3 argus_alert_receiver.py
```

To stop the script, press `Ctrl+C` in the terminal where it is running.

### Running as a Daemon

To run the receiver as a background daemon:

```bash
python3 argus_alert_receiver.py --daemon
```

The script will fork into the background, and the parent process will exit, allowing you to continue using your terminal. The Process ID (PID) of the daemon is stored in `/tmp/argus_receiver.pid`.

### Stopping the Daemon

To stop a running daemon process:

```bash
python3 argus_alert_receiver.py --stop
```

This command reads the PID from the PID file and sends a termination signal to the daemon, ensuring a clean shutdown.

### Specifying Host and Port

You can use the `--host` and `--port` arguments in conjunction with any of the modes above.

**Example:** To run as a daemon on a specific interface and port:

```bash
python3 argus_alert_receiver.py --host 192.168.1.100 --port 5000 --daemon
```

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
