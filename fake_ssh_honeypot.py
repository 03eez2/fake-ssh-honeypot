import socket
import threading
import logging
import time
from datetime import datetime
import os

# ANSI color codes for cool terminal output
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"
END = "\033[0m"

# ASCII Art Banner for 3Z BOOT
BANNER = f"""
{BLUE}{BOLD}
 _____            _                                        _   
|___ /   ____    | |__   ___  _ __   ___ _   _ _ __   ___ | |_ 
  |_ \  |_  /    | '_ \ / _ \| '_ \ / _ \ | | | '_ \ / _ \| __|
 ___) |  / /     | | | | (_) | | | |  __/ |_| | |_) | (_) | |_ 
|____/  /___|    |_| |_|\___/|_| |_|\___|\__, | .__/ \___/ \__|
                                         |___/|_|              
{BLUE}============================================================{END}
       {GREEN}Fake SSH Honeypot v1.0 - by xAI{END}
{BLUE}{BOLD}============================================================{END}
{RED}Warning: This is a honeypot to trap and log SSH attackers!{END}
Listening on port 22... Press Ctrl+C to stop.
"""

# Configure logging
logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def print_banner():
    """Display the cool ASCII banner."""
    print(BANNER)

def simulate_ssh_session(client_socket, client_address):
    """
    Simulate an SSH session, log credentials and commands.
    """
    try:
        # Log client connection
        logging.info(f"New connection from {client_address[0]}:{client_address[1]}")
        print(f"{GREEN}[+] New connection from {client_address[0]}:{client_address[1]}{END}")

        # Send SSH version string to make it look legit
        client_socket.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
        
        # Simulate SSH login prompt
        client_socket.send(b"login as: ")
        username = client_socket.recv(1024).decode('utf-8').strip()
        logging.info(f"Username attempt from {client_address[0]}: {username}")
        print(f"{BLUE}[*] Username attempt: {username}{END}")

        # Prompt for password
        client_socket.send(f"{username}@honeypot's password: ".encode('utf-8'))
        password = client_socket.recv(1024).decode('utf-8').strip()
        logging.info(f"Password attempt from {client_address[0]}: {password}")
        print(f"{BLUE}[*] Password attempt: {password}{END}")

        # Fake authentication failure to keep attacker engaged
        client_socket.send(b"\r\nPermission denied, please try again.\r\n")
        time.sleep(1)
        client_socket.send(b"login as: ")
        client_socket.recv(1024)  # Discard any further input

        # Simulate a shell prompt
        client_socket.send(b"\r\n$ ")
        while True:
            # Receive commands
            command = client_socket.recv(1024).decode('utf-8').strip()
            if not command:
                break
            logging.info(f"Command from {client_address[0]}: {command}")
            print(f"{RED}[!] Command: {command}{END}")

            # Simulate command output (basic responses)
            if command.lower() in ['whoami', 'id']:
                client_socket.send(b"uid=1000(user) gid=1000(user) groups=1000(user)\r\n")
            elif command.lower() == 'pwd':
                client_socket.send(b"/home/user\r\n")
            elif command.lower() == 'ls':
                client_socket.send(b"file1.txt  file2.txt\r\n")
            else:
                client_socket.send(b"bash: " + command.encode('utf-8') + b": command not found\r\n")
            
            client_socket.send(b"$ ")

    except Exception as e:
        logging.error(f"Error handling client {client_address[0]}: {str(e)}")
        print(f"{RED}[-] Error with {client_address[0]}: {str(e)}{END}")
    finally:
        client_socket.close()
        print(f"{GREEN}[-] Connection closed from {client_address[0]}:{client_address[1]}{END}")

def start_honeypot():
    """
    Start the fake SSH honeypot server.
    """
    # Create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        # Bind to port 22
       server_socket.bind(('0.0.0.0', 2222))
        server_socket.listen(5)
        print(f"{GREEN}[+] Honeypot started successfully!{END}")

        while True:
            # Accept incoming connections
            client_socket, client_address = server_socket.accept()
            # Start a new thread to handle the client
            client_thread = threading.Thread(
                target=simulate_ssh_session,
                args=(client_socket, client_address)
            )
            client_thread.start()

    except PermissionError:
        print(f"{RED}[-] Error: Permission denied. Run as root (sudo) to bind to port 22.{END}")
        logging.error("Permission denied: Must run as root to bind to port 22.")
    except Exception as e:
        print(f"{RED}[-] Server error: {str(e)}{END}")
        logging.error(f"Server error: {str(e)}")
    finally:
        server_socket.close()

def main():
    """
    Main function to initialize and run the honeypot.
    """
    print_banner()
    logging.info("Starting Fake SSH Honeypot")
    
    try:
        start_honeypot()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Shutting down honeypot...{END}")
        logging.info("Honeypot shut down")
    except Exception as e:
        print(f"{RED}[-] Fatal error: {str(e)}{END}")
        logging.error(f"Fatal error: {str(e)}")

if __name__ == "__main__":
    main()
