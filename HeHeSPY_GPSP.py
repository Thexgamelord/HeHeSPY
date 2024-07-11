import socket
import random
import string
import hashlib
import re
from urllib import response
import HeHeSPY as GPCM
import traceback

def create_rand_string(length):
    characters = string.ascii_uppercase
    return ''.join(random.choice(characters) for _ in range(length))

default_password = "pass"

def extract_values(data_received):
    try:
        data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
        uniquenick_pattern = r'\\uniquenick\\([^\\]+)'
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

def do_md5(data):
    md5 = hashlib.md5()
    md5.update(data.encode('utf-8'))
    return md5.hexdigest()

"""def generate_proof(user, data_received):
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
    login_response = "{}{}{}{}{}{}".format(pwdmd5," " * 48,user,client_chall,server_chall,pwdmd5)

    #buffer_str = pwdmd5 + ' ' * 48
    #buffer_str += user
    #buffer_str += server_chall
    #buffer_str += client_chall

    proof = do_md5(login_response)

    print(f"Proof Built: {proof}")
    return proof
"""

def create_user(data):
    gpcm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    gpcm_socket.connect(('localhost', 29900))  # Change this to your other server's address

    gpcm_socket.send(data)

    response = gpcm_socket.recv(1024)
    print(f"GPCM RESPONSE: {response}")
    gpcm_socket.close()
    if response == b'\\nur\\pid\\1\\final\\':
        print("user created")
        return "made user"
    elif response == b'\\error\\\\err\\513\\fatal\\\\errmsg\\That Nickname is taken.\\final\\':
        print("user is taken")
        return "taken"
    else:
        print("SOMETHING IS WRONG")
        return "error"

def main():
    host = "0.0.0.0"
    port = 29901
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
            # Accept an incoming client connection
            client_socket, client_address = server_socket.accept()
            print(f"Client connected from {client_address[0]}:{client_address[1]}")

            # Create a random challenge string

            try:
                while True:
                    # Receive data from the client
                    data_received = client_socket.recv(1024)
                    global gdata_received
                    gdata_received = data_received

                    if not data_received:
                        # No data received, the client might have disconnected
                        break
                    try:
                        print(r"Received: {0}".format(data_received))
                    except Exception as e:
                        print(f"error: {e}")
                    if data_received.startswith(b'\\newuser\\'):
                        # Respond with profile information
                        #response = r"\nur\\User Created\pid\\1\final\\"
                        #mkuser = GPCM.create_user(gdata_received, 0, True)
                        mkuser = create_user(gdata_received)
                        if mkuser == 'taken':
                            response = "\\error\\\\err\\513\\fatal\\\\errmsg\\That Nickname is taken.\\final\\"
                        elif mkuser == 'error':
                            response = "\\error\\\\err\\253\\fatal\\\\errmsg\\SOME RANDOM ERROR.\\final\\"
                            client_socket.send(response.encode("utf-8"))
                            client_socket.close()
                        else:
                            response = r"\nur\\User Created\pid\\1\final\\"
                        #GPCM.create_user(1, 'john_doe', 'password123', 'session_key_1', 0)
                        #response = r"\nur\\User Created\pid\\1\final\\"
                        print(f"Sending: {response}")
                        client_socket.send(response.encode("utf-8"))
                    else:
                        pass
                    if data_received.startswith(b'\\search\\'):
                        # Respond with profile information
                        data_str = data_received.decode('utf-8', errors='ignore')
                        uniquenick_pattern = r'\\uniquenick\\([^\\]+)'
                        uniquenick_match = re.search(uniquenick_pattern, data_str)
                        if uniquenick_match:
                            user = uniquenick_match.group(1)
                            #user_id = GPCM.user_to_id(user)
                            #response = f"\\bsr\\1\\nick\\Thexgameld\\uniquenick\\\\namespaceid\\1\\firstname\\firstname\\lastname\\lastname\\email\\thegamelord@proton.me\\bsr\\...\\bsrdone\\\\more\\0\\final\\"
                            if GPCM.user_exists(user):
                                user_id = GPCM.user_to_id(user)
                                print(f"{user} is a valid username")
                                response = f"\\bsr\\{user_id}\\nick\\{user}\\uniquenick\\{user}\\namespaceid\\0\\firstname\\\\lastname\\\\email\\{user}\\bsrdone\\0\\final\\"
                                print(f"Sending: {response}")
                                client_socket.send(response.encode("utf-8"))
                            else:
                                print(f"{user} is not a existing username")
                                response = "\\error\\\\err\\1538\\fatal\\\\errmsg\\The profile requested is invalid.\\final\\"
                                print(f"Sending: {response}")
                                client_socket.send(response.encode("utf-8"))
                                client_socket.close()
                        else:
                            print("some error")
                            response = "\\error\\\\err\\3328\\fatal\\\\errmsg\\Error with search.\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                    else:
                        pass

                    if data_received.startswith(b'\\others\\'):
                        # Respond with profile information
                        data_str = data_received.decode('utf-8', errors='ignore')
                        sess_id_pattern = r'\\sesskey\\([^\\]+)'
                        sess_id_match = re.search(sess_id_pattern, data_str)
                        if sess_id_match:
                            sess_id = sess_id_match.group(1)
                            username = GPCM.id_to_user(sess_id)
                            email = GPCM.user_to_email(username)
                            response = f"\\others\\\\o\\{sess_id}\\nick\\{username}\\uniquenick\\{username}\\first\\{username}\\last\\{username}\\email\\{email}\\odone\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                        else:
                            print("some error")
                            response = "\\error\\\\err\\ERROR CODE\\fatal\\\\errmsg\\ERROR MESSAGE\\id\\1\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                    else:
                        pass

                    if data_received.startswith(b'\\check\\'):
                        # Respond with nick information
                        data_str = data_received.decode('utf-8', errors='ignore')
                        email_pattern = r'\\email\\([^\\]+)'
                        email_match = re.search(email_pattern, data_str)
                        passwd_pattern = r'\\passenc\\([^\\]+)'
                        passwd_match = re.search(passwd_pattern, data_str)
                        if email_match and passwd_match:
                            user = email_match.group(1)
                            passwd = passwd_match.group(1)
                            response = "\\cur\\0\\pid\\1\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                        else:
                            #response = "\\error\\\\err\\513\\fatal\\\\errmsg\\Nick is taken.\\final\\"
                            response = "\\cur\\0\\pid\\1\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                        #response = r"\nur\\User Created\pid\\1\final\\"
                        #response = r"\final\\"
                            
                    else:
                        pass
                    if data_received.startswith(b'\\valid\\'):
                        # Respond with profile existance
                        data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
                        email_pattern = r'\\email\\([^\\]+)'
                        email_match = re.search(email_pattern, data_str)
                        if email_match:
                            email = email_match.group(1)
                        verify_email = GPCM.verify_user_email(email)
                        if verify_email == False:
                            response = r"\vr\0\final\\"
                        else:
                            response = r"\vr\1\final\\"
                        print(f"Sending: {response}")
                        client_socket.send(response.encode("utf-8"))
                    else:
                        pass
                    """
                    if data_received.startswith(b'\\nicks\\'):
                        # Respond with nick information
                        data_str = data_received.decode('utf-8', errors='ignore')
                        email_pattern = r'\\email\\([^\\]+)'
                        email_match = re.search(email_pattern, data_str)
                        passwd_pattern = r'\\pass\\([^\\]+)'
                        passwd_match = re.search(passwd_pattern, data_str)
                        passwdenc_pattern = r'\\passenc\\([^\\]+)'
                        passwdenc_match = re.search(passwdenc_pattern, data_str)
                        if email_match and passwd_match:
                            user = email_match.group(1)
                            passwd = passwd_match.group(1)
                            nicks = GPCM.find_users_nicks_by_email(email)
                            user_uniquenick = nicks[0]
                            user_nick = nicks[1]
                            #response = f"\\nr\\nick\\Thexgameld\\uniquenick\\Thexgameld\\ndone\\final\\"
                            response = f"\\nr\\\\nick\\{user_nick}\\uniquenick\\{user_uniquenick}\\ndone\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                        elif email_match and passwdenc_match:
                            user = email_match.group(1)
                            passwdenc = passwdenc_match.group(1)
                            email = email_match.group(1)
                            nicks = GPCM.find_users_nicks_by_email(email)
                            user_uniquenick = nicks[0]
                            user_nick = nicks[1]
                            #response = f"\\nr\\nick\\Thexgameld\\uniquenick\\Thexgameld\\ndone\\final\\"
                            response = f"\\nr\\\\nick\\{user_nick}\\uniquenick\\{user_uniquenick}\\ndone\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                        else:
                            response = "\\error\\\\err\\4\\fatal\\\\errmsg\\error\\id\\1\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                    else:
                        pass
                    """

                    if data_received.startswith(b'\\nicks\\'):
                        # Respond with nick information
                        data_str = data_received.decode('utf-8', errors='ignore')
                        email_pattern = r'\\email\\([^\\]+)'
                        email_match = re.search(email_pattern, data_str)
                        passwd_pattern = r'\\pass\\([^\\]+)'
                        passwd_match = re.search(passwd_pattern, data_str)
                        passwdenc_pattern = r'\\passenc\\([^\\]+)'
                        passwdenc_match = re.search(passwdenc_pattern, data_str)
                        if email_match and passwd_match:
                            user = email_match.group(1)
                            passwd = passwd_match.group(1)
                            if "@" in user:
                                nicks = GPCM.find_users_nicks_by_email(user, True)
                            else:
                                nicks = GPCM.find_users_nicks_by_email(user, False)
                            user_uniquenick = nicks[0]
                            user_nick = nicks[1]
                            #response = f"\\nr\\nick\\Thexgameld\\uniquenick\\Thexgameld\\ndone\\final\\"
                            response = f"\\nr\\\\nick\\{user_nick}\\uniquenick\\{user_uniquenick}\\ndone\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                        elif email_match and passwdenc_match:
                            user = email_match.group(1)
                            passwdenc = passwdenc_match.group(1)
                            email = email_match.group(1)
                            nicks = GPCM.find_users_nicks_by_email(email)
                            user_uniquenick = nicks[0]
                            user_nick = nicks[1]
                            #response = f"\\nr\\nick\\Thexgameld\\uniquenick\\Thexgameld\\ndone\\final\\"
                            response = f"\\nr\\\\nick\\{user_nick}\\uniquenick\\{user_uniquenick}\\ndone\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                        else:
                            response = "\\error\\\\err\\4\\fatal\\\\errmsg\\error\\id\\1\\final\\"
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                    else:
                        pass

                    if data_received.startswith(b"\\login\\"):
                        print("Building proof")

                        values = extract_values(data_received)  # Use data_received directly, which is binary
                        if values:
                            password, user, dserver_chall, client_chall = values
                            #proof_built = generate_proof(user, data_received)  # Pass the original binary data
                            #response = f"\\lc\\2\\sesskey\\{SESS_VAR}\\proof\\{proof_built}\\userid\\{SESS_VAR}\\profileid\\{SESS_VAR}\\uniquenick\\{user}\\lt\\{GS_LT}\\id\\1\\final\\"
                            
                            print(f"Sending: {response}")
                            client_socket.send(response.encode("utf-8"))
                        else:
                            print("Values not found in received data.")
                    if data_received.startswith(b'\\ka\\\\final\\'):
                        # Respond with PONG to PING
                        response = b'\\ka\\\\final\\'
                        print(f"Sending: {response}")
                        client_socket.send(response)
                    else:
                        pass



                    # ... Handle other cases like status, getprofile, newuser ...

            except Exception as ex:
                # Handle any exceptions
                print(f"An error occurred on line {ex.__traceback__.tb_lineno}: {ex}")
                first_conn = True
            finally:
                # Close the client socket
                client_socket.close()
                print(f"Client disconnected from {client_address[0]}:{client_address[1]}")
                first_conn = True

    except Exception as ex:
        # Handle any exceptions
        print(f"An error occurred: {str(ex)}")
    finally:
        # Close the server socket
        server_socket.close()

if __name__ == "__main__":
    main()