
# MSSQL - TDS Downgrade Attack

## Overview

This tool is designed to intercept and manipulate Tabular Data Stream (TDS) packets between a client and an MSSQL server. By initiating a Man-in-the-Middle (MitM) attack through ARP spoofing, it intercepts and downgrades the encryption of TDS login packet, allowing for the decryption of  MSSQL account username and password.

## Walkthrough & Details

MSSQL - TDS Downgrade Attack - https://medium.com/@giannisxristodoulakos/microsoft-sql-server-tds-downgrade-attack-4873098629b8

## Requirements
- **Internal Host**: An host on the internal network with root privileges, in order to execute the MitM attack (Linux OS)
- **Python**: 3.x
- **Dependencies**:
  - `arpspoof`: Required for ARP spoofing.
  - `iptables`: Required for traffic redirection.

## Installation

Clone the repository on the internal host:

```bash
https://github.com/NeCr00/Microsoft-SQL-TDS-Downgrade-Attack.git
cd Microsoft-SQL-TDS-Downgrade-Attack
```

Install any additional dependencies, if needed.
```bash
sudo apt install iptables
sudo apt install arpspoof
```

## Usage

To run the script, use the following command:

```bash
sudo python3 TDS_Downgrade.py -s <server_ip> -c <client_ip> -p <port>
```

### Command-line Arguments

- `-s`, `--server`: **Required**. Target MSSQL server IP address.
- `-c`, `--client`: **Required**. Client IP address for interception.
- `-p`, `--port`: Optional. Target MSSQL server port (default: 1433).

### Example

1. This command will start intercepting packets between the client at `192.168.1.101` and the MSSQL server at `192.168.1.100` on port `1433`.
```bash
sudo python3 TDS_Downgrade.py -s 192.168.1.100 -c 192.168.1.101
```

2.
Now by triggering an action (eg. Login attempt ) on client side , the application will try to connect to legitimate MSSQL server. However, due to Mitm attack,
the attacking host will receive the request , proceed with the appropiate modifications and then will forwrard the traffic on the MSSQL server. Eventually, it will
downgrade the connection and capture the login credentials on the Login packet.

## How It Works

1. **ARP Spoofing**: The script initiates ARP spoofing to trick the client and server into routing their traffic through the attacker's machine.
2. **Traffic Redirection**: With `iptables`, traffic destined for the MSSQL server is redirected to the specified port for interception.
3. **TDS Packet Interception and Modification**: 
   - The script captures TDS login packets and attempts to downgrade the encryption.
   - If successful, it retrieves and decrypts sensitive information, including usernames and passwords.
4. **Automatic Cleanup**: If the script is stopped, it will automatically stop ARP spoofing and clear iptables rules.


## Keywords

- **TDS packet interception**
- **Decrypt TDS packets**
- **ARP spoofing MSSQL**
- **MSSQL packet manipulation**
- **Downgrade MSSQL encryption**
- **Man-in-the-Middle MSSQL**
- **Decrypt usernames and passwords in MSSQL**
- **Network security penetration testing**
