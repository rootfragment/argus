import socket
import logging
import argparse
import sys
import os
import time

LOG_FILE = "argus_alerts.log"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 12345
PID_FILE = "/tmp/argus_receiver.pid"
RATE_LIMIT_SECONDS = 10

last_alert_times = {}

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - [ALERT FROM %(ip)s] - %(message)s",
        filename=LOG_FILE,
        filemode="a"
    )

def is_rate_limited(ip):
    current_time = time.time()
    last_time = last_alert_times.get(ip)

    if last_time and (current_time - last_time) < RATE_LIMIT_SECONDS:
        return True
    
    last_alert_times[ip] = current_time
    return False

def run_daemon(host, port):
    try:
        pid = os.fork()
        if pid > 0:
            with open(PID_FILE, "w") as f:
                f.write(str(pid))
            sys.exit(0)
    except OSError as e:
        logging.error(f"Failed to fork: {e}", extra={'ip': 'SYSTEM'})
        sys.exit(1)

    os.setsid()
    os.umask(0)
    main_loop(host, port)

def stop_daemon():
    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())
    except FileNotFoundError:
        print("PID file not found. Is the daemon running?", file=sys.stderr)
        sys.exit(1)
    except ValueError:
        print("Invalid PID in PID file.", file=sys.stderr)
        sys.exit(1)

    try:
        os.kill(pid, 15)
        logging.info("Daemon stopped.", extra={'ip': 'SYSTEM'})
        os.remove(PID_FILE)
    except ProcessLookupError:
        print(f"Process with PID {pid} not found. Removing stale PID file.", file=sys.stderr)
        os.remove(PID_FILE)
    except OSError as e:
        print(f"Failed to kill process {pid}: {e}", file=sys.stderr)
        sys.exit(1)

def main_loop(host, port):
    try:
        so = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        so.bind((host, port))
        logging.info(f"Receiver started. Listening on {host}:{port}", extra={'ip': 'SYSTEM'})
    except OSError as e:
        logging.error(f"Failed to bind to {host}:{port}. Is the port in use? Error: {e}", extra={'ip': 'SYSTEM'})
        sys.exit(1)
    
    while True:
        try:
            data, addr = so.recvfrom(4096)
            source_ip = addr[0]
            
            if is_rate_limited(source_ip):
                logging.warning(f"Rate limit exceeded for {source_ip}. Alert suppressed.", extra={'ip': 'SYSTEM'})
                continue

            message = data.decode('utf-8', errors='ignore').strip()
            
            for line in message.splitlines():
                if line: 
                    logging.info(line, extra={'ip': source_ip})
        except KeyboardInterrupt:
            logging.info("Receiver shutting down.", extra={'ip': 'SYSTEM'})
            so.close()
            break
        except Exception as e:
            logging.error(f"An error occurred: {e}", extra={'ip': 'SYSTEM'})

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argus UDP Alert Receiver")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST,
                        help=f"The host IP address to listen on. Defaults to {DEFAULT_HOST} (all interfaces).")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                        help=f"The port to listen on. Defaults to {DEFAULT_PORT}.")
    parser.add_argument("--daemon", action="store_true",
                        help="Run the receiver as a background daemon.")
    parser.add_argument("--stop", action="store_true",
                        help="Stop the running daemon process.")
    
    args = parser.parse_args()
    
    setup_logging()

    if args.stop:
        stop_daemon()
    elif args.daemon:
        run_daemon(args.host, args.port)
    else:
        main_loop(args.host, args.port)
