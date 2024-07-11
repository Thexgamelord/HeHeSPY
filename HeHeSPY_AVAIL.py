import socket
import re

def main():
    host = '0.0.0.0'  # Listen on all available network interfaces
    port = 27900

    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the specified host and port
    server_socket.bind((host, port))
    print(f"UDP server listening on {host}:{port}")

    while True:
        #data, client_address = server_socket.recvfrom(1024)  # Receive up to 256 bytes of data
        data, client_address = server_socket.recvfrom(4096) 
        
        #print(f"received: {data}")

        if data[0] == 0x09:
            try:
                print(f"[Availability Packet] {data}")
            except UnicodeDecodeError:
                pass
            game_name_length = data[5]  # Extract the game name length
            game_name = data[5:5 + game_name_length].decode('utf-8')[:-1]  # Extract the game name
            print(f"checking game: {game_name}")

            # Simulate the GameSpy service availability based on the game name
            game_support_check = is_game_supported(game_name)
            if game_support_check == "Online":
                response_status = 0  # Server is online
            elif game_support_check == "Offline":
                response_status = 1  # Server is not available
            elif game_support_check == "TempOffline":
                response_status = 2  # Server is not temporarily unavailable

            # Pack the response data
            response_data = bytearray([0xFE, 0xFD, 0x09])
            response_data.extend(response_status.to_bytes(4, byteorder='big'))

            # Append "nT2Mtz" to the response packet
            #response_data.extend(b'nT2Mtz')
            
            #print(f"built {response_data}")
            # Send the response back to the client
            server_socket.sendto(response_data, client_address)
        elif data[0] == 0x03:
            data_bytearray = bytearray(data)
            
            # Replace the binary '\x01N~' with an empty byte (b'')
            #replacement = b'\x03\x8e\xf3['
            #while replacement in data_bytearray:
            data_bytearray = data_bytearray.replace(b'\x00', b'/').replace(b'\x02', b'/').replace(b'\x01', b'/').replace(b'//', b'/').replace(b'//', b'')
            
            """data_pattern = r'\\localip0\\([^\\CIS\\]+)'
            data_match = re.search(data_pattern, data_bytearray)
            hb_data = data_match.group(1)"""
            
            
            # Use regular expressions to extract the data after 'localip0\\'
            pattern = re.compile(b'localip0(.*)')

            match = pattern.search(data)

            if match:
                result = match.group(1)
                hb_end = f"localip0" + result.decode('utf-8')
                print(f"Extracted data: {hb_end}")
            else:
                print("No match found.")
            
            print(f"[Heartbeat Packet] {data_bytearray}")
            
            # Define the data to be sent
            instant_key = b'\x01\x02\x03\x04'  # Example instant key
            server_keys = b'\x11\x12\x13'  # Example server keys
            total_server_keys = len(server_keys)
            player_keys = b'\x21\x22\x23'  # Example player keys
            total_player_keys = len(player_keys)
            team_key = b'\x31'  # Example team key
            total_team_keys = 1

            # Pack the data according to the specified format
            datad = (
                instant_key +
                b'\x00\x00' +
                bytes([total_server_keys]) +
                server_keys +
                b'\x00\x00' +
                bytes([total_player_keys]) +
                player_keys +
                b'\x00\x00' +
                bytes([total_team_keys]) +
                team_key
            )
            
            server_socket.sendto(datad, client_address)
            
        elif data[0] == 0x08:
            print(f"[Keep-alive Packet] {data}")
        elif data[0] == 0x01:
            print(f"[Challenge Packet] {data}")
        else:
            print(f"[Unknown Data Received] {data[0]} | {data}")

def is_game_supported(game_name):
        supported = ["swbfront2ps2", "swbfespsp", "mkdeceptionps2", "capricorn", "ut3pc", "srow2pc", "crysis", "conflictsops2", "flatout2pc","battlefield2","swbfront2pc","callofdutyps2"]
        temp_unavailable = []
        if game_name in supported:
            print(f"{game_name} is available")
            return "Online"
        elif game_name in temp_unavailable:
            print(f"{game_name} is temporarily not available")
            return "TempOffline"
            
        # elif game_name not in supported and game_name not in temp_unavailable:
            # print(f"{game_name} is temporarily not available")
            # return "TempOffline"
            
        elif game_name not in supported and game_name not in temp_unavailable:
            # TEMPORARY print(f"{game_name} is not available")
            # TEMPORARY return "Offline"
            print(f"{game_name} is available since there is no restriction")
            return "Online"

if __name__ == '__main__':
    main()
