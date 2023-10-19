import email
from pickle import FALSE
import socket
import random
import string
import hashlib
import re
import time
import threading
import redis
import gspassenc
import struct

global pass_enc
pass_enc = False
SESS_VAR = None  # Initialize SESS_VAR before the while loop
# Connect to the Redis server
redis_client = redis.StrictRedis(host='192.168.1.70', port=6379, db=0, decode_responses=True)

def show_error(errcode, errormsg):
    error_bld = f"\\error\\\\err\\{errcode}\\fatal\\\\errmsg\\{errormsg}\\final\\"
    return error_bld


def create_user(data_received, banned, external):
    data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
    print(data_received)
    email_pattern = r'\\email\\([^\\]+)'
    email_match = re.search(email_pattern, data_str)
    if email_match:
        email = email_match.group(1)
    print(f"got email: {email}")
    passwd = extract_passwd(data_received) #"YpeHhg__"
    values = extract_values(data_received)  # Use data_received directly, which is binary

    if external == True:
        passwd = gspassenc.decode(passwd)

    if values:
        passwddd, user, dserver_chall, client_chall = values

        print(f"Testing user creation username: {user} password: {passwd} ")
    else:
        print("Values not found in received data.")
    

    while redis_client.exists(f'Users:{user}'):
        print("ERROR USER EXISTS")
        return 'taken'

    unikey = generate_session_id()

    user_data = {
        'uniquenick': user,
        'email': email,
        'password': passwd,
        'sesskey': unikey,
        'banned': banned
    }
    redis_client.hmset(f'Users:{user}', user_data)
    redis_client.hmset(f'Users:{user}@{email}', user_data)
    print(f'[DB] SET Users:{user}', user_data)


def verify_user_email(email_to_check):
    # Get all keys that match the pattern Users:*
    user_keys = redis_client.keys('Users:*')

    for user_key in user_keys:
        # Retrieve the user's email from Redis
        email = redis_client.hget(user_key, 'email')
        # Check if the retrieved email matches the one to check
        if email_to_check in email:
            print("Email already in use")
            return True  # Email already in use
        else:
            print("FFS")
            return False

    print("Email not in use")

def user_exists(username):
    """
    Verify if a user with the given username exists in the Redis database.

    Args:
        username (str): The username (uniquenick) to check for.

    Returns:
        bool: True if the user exists, False if not.
    """
    user_id = redis_client.hget(f'Users:{username}', 'uniquenick')
    if user_id:
        # The user exists
        return True
    else:
        # The user doesn't exist
        return False


def get_user(user_id):
    user_data = redis_client.hgetall(f'Users:{user_id}')
    return user_data

def update_user(user_id, field, value):
    redis_client.hset(f'Users:{user_id}', field, value)

def delete_user(user_id):
    redis_client.delete(f'Users:{user_id}')


# Create a list to store used session IDs
used_session_ids = []
connected_clients = []

# When you want to send a message to all clients except the requester
def send_to_all_except_requester(message, requester_socket):
    for client_socket in connected_clients:
        if client_socket != requester_socket:
            client_socket.send(message.encode("utf-8"))
            print("sent to all but sender")

# Function to generate a random session ID and ensure it's unique
def generate_session_id():
    while True:
        session_id = random.randint(1, 999999)  # Adjust the range as needed
        if session_id not in used_session_ids:
            used_session_ids.append(session_id)
            return session_id


desired_data_rate = 400 * 1024

def generate_response(challenge, ac_challenge, secretkey, authtoken):
    """Generate a challenge response."""
    md5 = hashlib.md5()
    md5.update(ac_challenge)

    output = md5.hexdigest()
    output += ' ' * 0x30
    output += authtoken
    output += secretkey
    output += challenge
    output += md5.hexdigest()

    md5_2 = hashlib.md5()
    md5_2.update(output)

    return md5_2.hexdigest()


def create_rand_string(length):
    characters = string.ascii_uppercase
    return ''.join(random.choice(characters) for _ in range(length))

def create_rand_lt():
    characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]["
    lt = ''.join(random.choice(characters) for _ in range(22))
    lt += "__"  # Append "__" to the generated string
    return lt

default_password = "RIPSPY"


def extract_uniquenick(data_str):
    uniquenick_pattern = r'\\uniquenick\\([^\\]+)'
    uniquenick_match = re.search(uniquenick_pattern, data_str)
    if uniquenick_match:
        user = uniquenick_match.group(1)
        return user
    else:
        return None

def extract_user(data_str):
    user_pattern = r'\\user\\([^\\]+)'
    user_match = re.search(user_pattern, data_str)
    if user_match:
        user = user_match.group(1)
        return user
    else:
        return None

def extract_nick(data_str):
    nick_pattern = r'\\nick\\([^\\]+)'
    nick_match = re.search(nick_pattern, data_str)
    if nick_match:
        user = nick_match.group(1)
        return user
    else:
        return None

def extract_email(data_str):
    email_pattern = r'\\email\\([^\\]+)'
    email_match = re.search(email_pattern, data_str)
    if email_match:
        email = email_match.group(1)
        return email
    else:
        return None

def extract_authtoken(data_str):
    authtoken_pattern = r'\\authtoken\\([^\\]+)'
    authtoken_match = re.search(authtoken_pattern, data_str)
    if authtoken_match:
        authtoken = authtoken_match.group(1)
        return authtoken
    else:
        return None

def extract_passwd(data_received):
    try:
        data_str = data_received.decode('utf-8', errors='ignore')
        passenc_pattern = r'\\passenc\\([^\\]+)'
        passenc_match = re.search(passenc_pattern, data_str)
        passwordenc_pattern = r'\\passwordenc\\([^\\]+)'
        passwordenc_match = re.search(passwordenc_pattern, data_str)
        password_pattern = r'\\password\\([^\\]+)'
        password_match = re.search(password_pattern, data_str)
        if passenc_match:
            password = passenc_match.group(1)
            return password
        elif passwordenc_match:
            password = passwordenc_match.group(1)
            return password
        elif password_match:
            password = password_match.group(1)
            return password
        else:
            return None
    except Exception as e:
        print(f"Error processing data: {e}")
        return None


def extract_values(data_received):
    try:
        data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string

        user = extract_uniquenick(data_str)
        if user:
            return default_password, user, None, None  # Return user information

        user = extract_user(data_str)
        if user:
            return default_password, user, None, None  # Return user information

        user = extract_nick(data_str)
        if user:
            return default_password, user, None, None  # Return user information

        authtoken = extract_authtoken(data_str)
        if authtoken:
            return default_password, authtoken, None, None  # Return authtoken information

        return None
    except Exception as e:
        print(f"Error processing data: {e}")
        return None

def generate_lc_II_response(client_socket, data_received, first_conn, proof_built, GS_LT):
    try:
        data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string

        user_pattern = r'\\user\\([^\\]+)'
        uniquenick_pattern = r'\\uniquenick\\([^\\]+)'
        authtoken_pattern = r'\\authtoken\\([^\\]+)'

        user_match = re.search(user_pattern, data_str)
        uniquenick_match = re.search(uniquenick_pattern, data_str)
        authtoken_match = re.search(authtoken_pattern, data_str)

        if user_match:
            user = user_match.group(1)
            response = f"\\lc\\2\\sesskey\\{SESS_VAR}\\proof\\{proof_built}\\userid\\{SESS_VAR}\\profileid\\{SESS_VAR}\\user\\{user}\\lt\\{GS_LT}\\id\\1\\final\\"
            print(f"Sending: {response}")
            first_conn = True
            client_socket.send(response.encode("utf-8"))
        elif uniquenick_match:
            user = uniquenick_match.group(1)
            response = f"\\lc\\2\\sesskey\\{SESS_VAR}\\proof\\{proof_built}\\userid\\{SESS_VAR}\\profileid\\{SESS_VAR}\\uniquenick\\{user}\\lt\\{GS_LT}\\id\\1\\final\\"
            print(f"Sending: {response}")
            first_conn = True
            client_socket.send(response.encode("utf-8"))
        elif authtoken_match:
            user = authtoken_match.group(1)
            response = f"\\lc\\2\\sesskey\\{SESS_VAR}\\proof\\{proof_built}\\userid\\{SESS_VAR}\\profileid\\{SESS_VAR}\\uniquenick\\{user}\\lt\\{GS_LT}\\id\\1\\final\\"
            print(f"Sending: {response}")
            first_conn = True
            client_socket.send(response.encode("utf-8"))
          
        else:
            return None
    except Exception as e:
        print(f"Error processing data: {e}")




"""
def extract_values(data_received):
    try:
        data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
        uniquenick_pattern = r'\\user\\([^\\]+)'
        server_chall_pattern = r'\\challenge\\([^\\]+)'
        client_chall_pattern = r'\\login\\\\challenge\\([^\\]+)'

        uniquenick_match = re.search(uniquenick_pattern, data_str)
        server_chall_match = re.search(server_chall_pattern, data_str)
        client_chall_match = re.search(client_chall_pattern, data_received.decode('utf-8', errors='ignore'))

        if uniquenick_match and server_chall_match and client_chall_match:
            user = uniquenick_match.group(1)
            server_chall = server_chall_match.group(1)
            client_chall = client_chall_match.group(1)
            return default_password, user, server_chall, client_chall
        else:
            return None
    except Exception as e:
        print(f"Error processing data: {e}")
        return None
    """
def do_md5(data):
    md5 = hashlib.md5()
    md5.update(data.encode('utf-8'))
    return md5.hexdigest()

def generate_proof(user, data_received):
    """
    Generate a challenge proof. [REDIS]

    The proof is practically the same thing as the response, except it has
    the challenge and the secret key swapped.
    """
    # Extract the client challenge from data_received
    client_chall_pattern = br'\\login\\\\challenge\\([^\\]+)'
    client_chall_match = re.search(client_chall_pattern, data_received)

    if client_chall_match:
        client_chall = client_chall_match.group(1).decode('utf-8', errors='ignore')
        print(f"client chall: {client_chall}")
    else:
        print("Client challenge not found in received data.")
        return None

    # Attempt to retrieve the user's password from Redis based on the user's uniquenick
    try:
        user_password = redis_client.hget(f'Users:{user}', 'password')
    except redis.RedisError as e:
        print(f'Error retrieving password from Redis: {e}')
        user_password = None

    if user_password is None:
        print(f"User '{user}' not found in the database.")
        return None
    else:
        print(f"User '{user}' password retrieved from the database: {user_password}")
        if pass_enc:
            decrypted_passwdd = gspassenc.decode(user_password)
        else:
            decrypted_passwdd = user_password
        print(f"real password: {decrypted_passwdd}")
    
    # Check if the user is banned
    user_banned = redis_client.hget(f'Users:{user}', 'banned')
    if user_banned == '1':
        # User is banned, send an error message
        print(f"User '{user}' is banned.")
        error_response = "\\error\\\\err\\256\\fatal\\\\errmsg\\User is banned.\\final\\"
        return error_response
    else:
        print(f"{user} passed ban checks!")

    pwdmd5 = do_md5(decrypted_passwdd)
    print(f"USER:{user},CC:{client_chall},SC:{server_chall},pwd:{pwdmd5}")
    login_response = "{}{}{}{}{}{}".format(pwdmd5, " " * 48, user, server_chall, client_chall, pwdmd5)

    # buffer_str = pwdmd5 + ' ' * 48
    # buffer_str += user
    # buffer_str += server_chall
    # buffer_str += client_chall

    proof = do_md5(login_response)

    print(f"Proof Built: {proof}")
    return proof

def generate_Pproof(user, data_received):
    """
    Generate a challenge proof.

    The proof is practically the same thing as the response, except it has
    the challenge and the secret key swapped.
    """
    # Extract the client challenge from data_received
    client_chall_pattern = br'\\login\\\\challenge\\([^\\]+)'
    client_chall_match = re.search(client_chall_pattern, data_received)

    if client_chall_match:
        client_chall = client_chall_match.group(1).decode('utf-8', errors='ignore')
        print(f"client chall: {client_chall}")
    else:
        print("Client challenge not found in received data.")
        return None

    pwdmd5 = do_md5(default_password)
    print(f"USER:{user},CC:{client_chall},SC:{server_chall},pwd:{pwdmd5}")
    login_response = "{}{}{}{}{}{}".format(pwdmd5," " * 48,user,server_chall,client_chall,pwdmd5)

    #buffer_str = pwdmd5 + ' ' * 48
    #buffer_str += user
    #buffer_str += server_chall
    #buffer_str += client_chall

    proof = do_md5(login_response)

    print(f"Proof Built: {proof}")
    return proof

def handle_status_request(client_socket, data_received):
    # Extract the game name from the data_received
    game_name = data_received[5:].decode('utf-8', errors='ignore')
    
    game_name_pattern = br'\\locstring\\([^:///]+)'
    game_name_match = re.search(game_name_pattern, data_received)
    game_name = game_name_match.group(1).decode('utf-8', errors='ignore')
    print(f"gamename for status {game_name}")

    #available (status = 0)
    #not available (status = 1)
    #temp not available (status = 2)
    status = 0

    # Build the response packet
    response = struct.pack('BIII', 0xFE, 0xFD, 0x09, status)

    # Send the response
    client_socket.send(response)


def handle_client(client_socket, first_conn):
    global SESS_VAR
    # Separate function to handle each client
    try:
        while True:
            if first_conn:
                GS_LT = create_rand_lt()
                global server_chall
                server_chall = create_rand_string(10)
                #SESS_VAR = SESS_VAR = redis_client.hget(f'Users:{user}', 'sesskey')#get sesskey from user
                first_conn = False
                # Respond with the initial challenge
                response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
            else:
                pass

            # Receive data from the client
            data_received = client_socket.recv(1024)
            global gdata_received
            gdata_received = data_received

            if not data_received:
                # No data received, client might have disconnected
                # Reset the first_conn flag for the next connection
                first_conn = True
                break  # Exit the loop when the client disconnects
            try:
                print(r"Received: {0}".format(data_received))
            except Exception as e:
                print(f"error: {e}")

            if data_received.startswith(b"\\login\\"):
                print("Building proof for login")

                values = extract_values(data_received)  # Use data_received directly, which is binary
                if values:
                    password, user, dserver_chall, client_chall = values
                    proof_built = generate_proof(user, data_received)  # Pass the original binary data
                    #generate_lc_II_response(client_socket, data_received, first_conn, proof_built, GS_LT)
                    # Retrieve user data
                    user_data = get_user(1)
                    print(user_data)  # This will print the user's data as a dictionary
                    global SESS_VAR
                    SESS_VAR = redis_client.hget(f'Users:{user}', 'sesskey')#get sesskey from user
                    generate_lc_II_response(client_socket, data_received, first_conn, proof_built, GS_LT)
                    print(f"{user} logged in @ {SESS_VAR}")

                    #response = f"\\lc\\2\\sesskey\\{SESS_VAR}\\proof\\{proof_built}\\userid\\{SESS_VAR}\\profileid\\{SESS_VAR}\\user\\{user}\\lt\\{GS_LT}\\id\\1\\final\\"
                    print(f"Sending: {response}")
                    if redis_client.exists(f'Users:{user}'):
                        print("FOUND USER AND but not UPDATING SESSKEY")
                        #upd_user_sessid = {'sesskey': SESS_VAR,}
                        #redis_client.hmset(f'Users:{user}', upd_user_sessid)
                    else:
                        print("USER NOT FOUND and NOT UPDATING SESSKEY")
                    
                    first_conn = False
                    response2 = f"\\bm\\100\\f\\{SESS_VAR}\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0|qm|0\\final\\"
                    print(f"Sending: {response2}")
                    client_socket.send(response2.encode("utf-8"))
                else:
                    print("Values not found in received data.")
                    response = "\\error\\\\err\\265\\fatal\\\\errmsg\\The uniquenick provided was incorrect.\\id\\1\\final\\"
                    first_conn = True
                    print(f"Sending: {response}")
                    client_socket.send(response.encode("utf-8"))
            else:
                pass

            if data_received.startswith(b'\\newuser\\'):
                # Respond with profile information
                #response = r"\nur\\User Created\pid\\1\final\\"
                mkuser = create_user(data_received, 0, False)
                if mkuser == 'taken':
                    response = "\\error\\\\err\\513\\fatal\\\\errmsg\\Nick is taken.\\final\\"
                else:
                    response = r"\nur\\User Created\pid\\1\final\\"
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
            else:
                pass

            if data_received.startswith(b'\\status\\'):
                #response = "\\msg\|s|1|ss|Online|ls|UK|ip|192.168.1.120|p|29900|qm|1\\final\\"
                handle_status_request(client_socket, data_received)
                print("handling a status request")
                #print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
            else:
                pass

            if data_received.startswith(b'\\addbuddy\\'):
                data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
                bm_reason_pattern = r'\\reason\\([^\\]+)'
                bm_reason_match = re.search(bm_reason_pattern, data_str)
                bm_reason = uniquenick_match.group(1)
                response = f"\\bm\\2\\f\\2\\msg\\{bm_reason}\\"
                response2 = "\\bm\\100\\f\\2\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0|qm|0\\final\\"
                #response = "\\error\\\\err\\2\\fatal\\\\errmsg\\Failed to Send Friend req\\id\\1\\final\\"
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
                #send_to_all_except_requester(response, client_socket)
            else:
                pass

            if data_received.startswith(b"\\logout\\"):
                print("client logging out")
                response = "\\error\\\\err\\259\\fatal\\\\errmsg\\logging out!\\final\\"
                first_conn = True
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
                client_socket.close()
            else:
                pass

            if data_received.startswith(b'\\msg\\\\final\\'):
                # Respond with PONG to PING
                response = "\\msg\\1\\final\\"
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
            else:
                pass

            if data_received.startswith(b"\\getprofile\\"):
                print("client asking for profile")
                #response = "\\error\\\\err\\259\\fatal\\\\errmsg\\logging out!\\final\\"
                #print(f"Sending: {response}")
                #client_socket.send(response.encode("utf-8"))
                pass
            else:
                pass

            # ... Handle other cases like status, getprofile, newuser ...

    except Exception as ex:
        # Handle any exceptions
        print(f"An error occurred: {str(ex)}")
        first_conn = True
    finally:
        # Close the client socket
        client_socket.close()
        first_conn = True
        print("Client disconnected.")

def main():
    host = "0.0.0.0"
    port = 29900
    first_conn = True

    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Bind the socket to the host and port
        server_socket.bind((host, port))

        # Start listening for incoming connections
        server_socket.listen()
        print(f"Server is listening on {host}:{port}")

        while True:
            global start_time
            start_time = time.time()
            
            # Accept an incoming client connection
            client_socket, client_address = server_socket.accept()
            print(f"Client connected from {client_address[0]}:{client_address[1]}")
            # Add this line to add a connected client's socket to the list
            connected_clients.append(client_socket)

            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket,first_conn))
            client_thread.start()

    except Exception as ex:
        # Handle any exceptions
        print(f"An error occurred: {str(ex)}")
    finally:
        # Close the server socket
        server_socket.close()
        print("Server socket closed.")

if __name__ == "__main__":
    main()
