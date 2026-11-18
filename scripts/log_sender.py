"""
Replay a log file to a ULPF syslog listener over UDP or TCP at a fixed rate.

    python scripts/log_sender.py --file demo_data/mixed_formats.log --eps 500
"""
import socket
import time
import argparse
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def send_logs(host, port, proto, file_path, eps):
    # Relative paths: current directory first, then the project root
    if not os.path.isabs(file_path) and not os.path.exists(file_path):
        file_path = os.path.join(PROJECT_ROOT, file_path)

    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        sys.exit(1)

    print(f"Starting Log Sender to {host}:{port} via {proto.upper()}")
    print(f"Source file: {file_path}")
    print(f"Rate: {eps} events per second")

    sock_type = socket.SOCK_DGRAM if proto.lower() == 'udp' else socket.SOCK_STREAM
    sock = socket.socket(socket.AF_INET, sock_type)
    
    if proto.lower() == 'tcp':
        try:
            sock.connect((host, port))
        except Exception as e:
            print(f"Connection failed: {e}")
            sys.exit(1)

    delay = 1.0 / eps if eps > 0 else 0
    count = 0
    
    # Pre-read and prepare lines into 8KB network chunks to eliminate overhead
    prepared_data = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            current_chunk = bytearray()
            lines_in_chunk = 0
            for line in f:
                line = line.strip()
                if not line: continue
                data = line.encode('utf-8')
                
                if proto.lower() == 'tcp':
                    data += b'\n'
                    prepared_data.append((data, 1))
                else:
                    # Batch for UDP
                    if len(current_chunk) + len(data) + 1 > 8192:
                        prepared_data.append((bytes(current_chunk), lines_in_chunk))
                        current_chunk = bytearray()
                        lines_in_chunk = 0
                    if current_chunk:
                        current_chunk.extend(b'\n')
                    current_chunk.extend(data)
                    lines_in_chunk += 1
            
            if current_chunk:
                prepared_data.append((bytes(current_chunk), lines_in_chunk))
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    if not prepared_data:
        print("File is empty.")
        return

    try:
        print("Streaming started... press CTRL+C to stop.")
        start_time = time.perf_counter()
        while True:
            for data, num_lines in prepared_data:
                if proto.lower() == 'tcp':
                    sock.sendall(data)
                else:
                    sock.sendto(data, (host, port))
                
                previous = count
                count += num_lines
                if count // 1000 != previous // 1000:
                    print(f"Sent {count} events...")
                
                if delay > 0:
                    expected_time = count * delay
                    actual_time = time.perf_counter() - start_time
                    sleep_time = expected_time - actual_time
                    if sleep_time > 0.005:
                        time.sleep(sleep_time)
    except KeyboardInterrupt:
        print(f"\nStopped by user. Total sent: {count}")
    finally:
        sock.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simulate network log ingestion by sending local log files over UDP/TCP.")
    parser.add_argument('--host', default='127.0.0.1', help='Target IP address')
    parser.add_argument('--port', type=int, default=5514, help='Target port')
    parser.add_argument('--proto', choices=['udp', 'tcp'], default='udp', help='Protocol')
    parser.add_argument('--file', default='demo_data/mixed_formats.log', help='Log file to send')
    parser.add_argument('--eps', type=float, default=50.0, help='Events per second (0 for unlimited)')
    
    args = parser.parse_args()
    send_logs(args.host, args.port, args.proto, args.file, args.eps)
