import socket
import logging
import argparse
import sys


LOG_FILE = "argus_alerts.log"
DEFAULT_HOST = "0.0.0.0"  
DEFAULT_PORT = 12345

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - [ALERT FROM %(ip)s] - %(message)s",
        filename=LOG_FILE,
        filemode="a"
    )
    
def main(host, port):
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
    parser.add_argument("-h", "--host", type=str, default=DEFAULT_HOST,
                        help=f"The host IP address to listen on. Defaults to {DEFAULT_HOST} (all interfaces).")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                        help=f"The port to listen on. Defaults to {DEFAULT_PORT}.")
    
    args = parser.parse_args()
    
    setup_logging()
    main(args.host, args.port)
