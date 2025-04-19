            
============================================================
       Fake SSH Honeypot v1.0 - by 3z
============================================================
Warning: This is a honeypot to trap and log SSH attackers!
Listening on port 22... Press Ctrl+C to stop.

[+] Honeypot started successfully!


Fake SSH Honeypot is a Python-based tool designed to simulate a fake SSH server to attract and log malicious login attempts. It listens for incoming connections, mimics an SSH login prompt, and logs the attacker's IP address, attempted usernames, passwords, and commands to a file (honeypot.log). This tool uses threading to handle multiple connections simultaneously, making it a lightweight and effective honeypot for monitoring SSH-based attacks.

Features
- Simulates an SSH server on a specified port (default: 2222 for Windows compatibility, 22 on Linux with admin rights).
- Logs client IP addresses, usernames, passwords, and commands to honeypot.log.
- Handles multiple connections using threading.
- Cross-platform support (Linux and Windows).

Prerequisites
- Python 3.x: Ensure Python is installed on your system. Download from python.org.
- Administrator Privileges (Optional): Required if you want to bind to port 22 (Linux: use sudo, Windows: run as administrator).
- SSH Client: To test the honeypot


**Installation**

Clone the repository from GitHub:

git clone https://github.com/03eez2/fake-ssh-honeypot.git
cd fake_ssh_honeypot

Run the Honeypot:
On Linux:

To use the default port 22, run with sudo:
sudo python fake_ssh_honeypot.py


On Windows:

python fake_ssh_honeypot.py


