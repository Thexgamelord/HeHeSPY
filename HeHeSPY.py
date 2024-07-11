import base64
import socket
import random
import string
import hashlib
import re
import time
import threading
from urllib import request, response
import urllib3
import redis
#import gspassenc
import struct
import passdec
#import gsmsalg
import traceback
from enum import Enum, unique
import spymail
import requests
import json
import select
import os
#import sqlite3

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


def Gdecode(password):
    # Convert Gamespy Base64 to Standard Base 64
    password = password.replace('_', '=').replace('[', '+').replace(']', '/')
    # Decode password
    password_bytes = base64.b64decode(password)
    return game_spy_encode_method(password_bytes).decode("utf-8")

def game_spy_encode_method(pass_bytes):
    a = 0
    num = 0x79707367  # gamespy
    result = bytearray()

    for b in pass_bytes:
        num = game_spy_byte_shift(num)
        a = num % 0xFF
        result.append(b ^ a)

    return bytes(result)

def game_spy_byte_shift(num):
    c = (num >> 16) & 0xffff
    a = num & 0xffff

    c *= 0x41a7
    a *= 0x41a7
    a += ((c & 0x7fff) << 16)

    if a < 0:
        a &= 0x7fffffff
        a += 1

    a += (c >> 15)

    if a < 0:
        a &= 0x7fffffff
        a += 1

    return a

def gspydecode(password):
    decoded_password = Gdecode(password)
    return decoded_password



# Load the private key
# Load the private key from a file
private_key_file = 'priv.key'
try:
    with open(private_key_file, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b"REDACTED",  # If the key is not encrypted
            backend=default_backend()
        )
except FileNotFoundError:
    print("The required private key (priv.key) is missing")

global usr_BANNED
usr_BANNED = False
global pass_enc
pass_enc = False
global Badpass
Badpass = False
SESS_VAR = None  # Initialize SESS_VAR before the while loop
global authtoken_req
authtoken_req = None

"""
OG GAMESPY NOTES

NICKNAMES CAN ONLY BE 20 CHARACTERS LONG
UNIQUENICKNAMES CAN ONLY BE 15 CHARACTERS LONG
"""


#db = sqlite3.connect("hehespy.db")
#cur = db.cursor()

# Connect to the Redis server
redis_client = redis.StrictRedis(host='192.168.1.153', port=6379, db=0, decode_responses=True)

#START OF PASSENC

def passenc_encode(password):
    # Get password string as UTF8 String, Convert to Base64
    password_bytes = password.encode('utf-8')
    pass_encoded = base64.b64encode(game_spy_encode_method(password_bytes))

    # Convert Standard Base64 to Gamespy Base 64
    pass_encoded = pass_encoded.decode('utf-8').replace('=', '_').replace('+', '[').replace('/', ']')
    return pass_encoded

def passenc_decode(password):
    # Convert Gamespy Base64 to Standard Base 64
    password = password.replace('_', '=').replace('[', '+').replace(']', '/')
    # Decode password
    password_bytes = base64.b64decode(password)
    return game_spy_encode_method(password_bytes).decode('utf-8')

def game_spy_encode_method(pass_bytes):
    num = 0x79707367  # gamespy
    pass_bytes = bytearray(pass_bytes)
    for i in range(len(pass_bytes)):
        num = game_spy_byte_shift(num)
        a = num % 0xFF
        pass_bytes[i] ^= a
    return bytes(pass_bytes)


def game_spy_byte_shift(num):
    c = (num >> 16) & 0xffff
    a = num & 0xffff

    c *= 0x41a7
    a *= 0x41a7
    a += ((c & 0x7fff) << 16)

    if a < 0:
        a &= 0x7fffffff
        a += 1

    a += (c >> 15)

    if a < 0:
        a &= 0x7fffffff
        a += 1

    return a

#END OF PASSENC

def do_sha256(data):
    s256 = hashlib.sha256()
    s256.update(data.encode('utf-8'))
    return s256.hexdigest()

def show_error(errcode, errormsg):
    error_bld = f"\\error\\\\err\\{errcode}\\fatal\\\\errmsg\\{errormsg}\\final\\"
    return error_bld


def web_create_user(user,nick,email,passwd,firstname,lastname,namespaceid,partnerid,emailconfirm):
    
    """
    for user creation from web page
    """
    

    while redis_client.exists(f'Users:{user}'):
        print("ERROR USER EXISTS")
        return 'taken'

    unikey = generate_session_id()
    profileid = generate_profile_id()

    user_data = {
        'uniquenick': user,
        'nick':nick,
        'email': email,
        'password': passwd,
        'namespaceid': namespaceid,
        'partnerid': partnerid,
        'sesskey': unikey,
        'banned': 0,
        'emailverified':0,
        'uuid':'',
        'balance':'15'
    }
    redis_client.hmset(f'Users:{user}', user_data)
    #redis_client.hmset(f'Users:{user}@{email}', user_data)
    if emailconfirm == "on":
        spymail.send_email_signup(email, user)
    print(f'[DB] SET Users:{user}', user_data)
    return profileid ,None

def create_user(data_received, banned, external):
    data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
    print(data_received)
    email_pattern = r'\\email\\([^\\]+)'
    email_match = re.search(email_pattern, data_str)
    if email_match:
        email = email_match.group(1)
    print(f"got email: {email}")
    passwd = extract_passwd(data_received) #do_sha256(extract_passwd(data_received)) #"YpeHhg__"
    values = extract_values(data_received)  # Use data_received directly, which is binary

    if external == True:
        passwd = passdec.decode(passwd)

    if values:
        passwddd, user, dserver_chall, client_chall = values

        print(f"Testing user creation username: {user} password: {passwd} ")
    else:
        print("Values not found in received data.")
    

    while redis_client.exists(f'Users:{user}'):
        print("ERROR USER EXISTS")
        return None, 'taken'

    unikey = generate_session_id()
    profileid = generate_profile_id()

    user_data = {
        'uniquenick': user,
        'nick':'',
        'email': email,
        'password': passwd,
        'sesskey': unikey,
        'banned': banned,
        'emailverified':0,
        'firstname':'',
        'lastname':'',
        'uuid':'',
        'balance':'15'
    }
    redis_client.hmset(f'Users:{user}', user_data)
    #redis_client.hmset(f'Users:{user}@{email}', user_data)
    spymail.send_email_signup(email, user)
    print(f'[DB] SET Users:{user}', user_data)
    return profileid ,None

def create_profile(data_received, banned, external):
    data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
    print("creating profile")
    email_pattern = r'\\email\\([^\\]+)'
    email_match = re.search(email_pattern, data_str)
    if email_match:
        email = email_match.group(1)
    print(f"got email: {email}")
    passwd = extract_passwd(data_received) #"YpeHhg__"
    values = extract_values(data_received)  # Use data_received directly, which is binary

    if external == True:
        passwd = passenc_decode(passwd)
        #passwd = gspassenc.decode(passwd)

    if values:
        passwddd, user, dserver_chall, client_chall = values

        print(f"Testing user creation username: {user} password: {passwd} ")
    else:
        print("Values not found in received data.")
    

    while redis_client.exists(f'Profiles:{user}'):
        print("ERROR USER EXISTS")
        return 'taken'

    uniproid = generate_profile_id()

    user_data = {
        'profileid':uniproid,
        'userid': user_to_id(user),
        'nick':user,
        'serverflag':'0',
        'status': '0',
        'statstring':"HeHeSPY",
        'firstname':'',
        'lastname':'',
        'icquin':'',
        'quietflags':'',
        'homepage':'thexgamelord.uk.to',
        'zipcode':'00000',
        'countrycode':'UK',
        'lon':'0.0000',
        'lat':'0.0000',
        'loc':'',
        'birthday':'',
        'sex':'0',
        'pmask':'0',
        'aim':'',
        'pic':'',
        'occ':'0',
        'ind':'0',
        'inc':'0',
        'mar':'0',
        'chc':'0',
        'i1':'',
        'o1':'',
        'conn':'0',
        'quietflags':'0',
    }
    redis_client.hmset(f'Profiles:{user}', user_data)
    #redis_client.hmset(f'Users:{user}@{email}', user_data)
    print(f'[DB] SET Users:{user}', user_data)


def verify_user_email(email_to_check):
    # Get all keys that match the pattern Users:*
    user_keys = redis_client.keys('Users:*')

    for user_key in user_keys:
        # Retrieve the user's data
        user_data = redis_client.hgetall(user_key)
        if user_data.get('email') == email_to_check:
            return True  # Email already in use

    return False  # Email not in use

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

def get_names_by_sesskey(sesskey_to_find):
    # Get all keys that match the pattern Users:*
    user_keys = redis_client.keys('Users:*')

    for user_key in user_keys:
        # Retrieve the user's data
        user_data = redis_client.hgetall(user_key)
        if user_data.get('sesskey') == sesskey_to_find:
            return user_data.get('firstname'), user_data.get('lastname')  # Return the uniquenick

    return "DEFAULT", "DEFAULT"  # Session key not found

def update_user_uuid(uniquenick, password, user_uuid):
    user_keys = redis_client.keys('Users:*')

    for user_key in user_keys:
        # Retrieve the user's data
        user_data = redis_client.hgetall(user_key)
        if user_data.get('uniquenick') == uniquenick:
            print("found user")
            if user_data.get('password') == password:
                print("password was correct")
                redis_client.hset(f'Users:{uniquenick}', "uuid", user_uuid)
                return "uuidset"
            else:
                print("password incorrect")
                return "badpass"
        else:
            print("uniquenick not found")
            return "badnick"

def user_to_id(user_id):
    user_data = redis_client.hgetall(f'Users:{user_id}')
    sesskey = user_data.get('sesskey')
    sesskey = int(sesskey)
    return sesskey

def find_users_names_by_email(email_to_check):
    user_keys = redis_client.keys('Users:*')
    
    for user_key in user_keys:
        user_data = redis_client.hgetall(user_key)
        if 'email' in user_data and user_data['email'] == email_to_check:
            firstname = user_data.get('firstname')
            lastname = user_data.get('lastname')
            return firstname, lastname

def find_users_nicks_by_email(email_to_check, emailcheck=True):
    user_keys = redis_client.keys('Users:*')
    if emailcheck == True:
        for user_key in user_keys:
            user_data = redis_client.hgetall(user_key)
            if 'email' in user_data and user_data['email'] == email_to_check:
                uniquenick = user_data.get('uniquenick')
                nickname = user_data.get('nick')
                return uniquenick, nickname
    else:
        for user_key in user_keys:
            user_data = redis_client.hgetall(user_key)
            uniquenick = user_data.get('uniquenick')
            nickname = user_data.get('nick')
            return uniquenick, nickname

def user_to_email(user_id):
    user_data = redis_client.hgetall(f'Users:{user_id}')
    email = user_data.get('email')
    return email

def user_to_names(user):
    user_keys = redis_client.keys('Users:*')
    
    for user_key in user_keys:
        user_data = redis_client.hgetall(user_key)
        print(f"found names {user_data['firstname']} {user_data['lastname']} from user {user}")
        return user_data['firstname'], user_data['lastname']

def id_to_user(sess_id):
    user_keys = redis_client.keys('Users:*')
    
    for user_key in user_keys:
        user_data = redis_client.hgetall(user_key)
        if 'sesskey' in user_data and user_data['sesskey'] == sess_id:
            # Return the user who has the matching session key
            print(f"found {user_data['uniquenick']} from id {sess_id}")
            return user_data['uniquenick']
    
    # If the sess_id is not found in any user, return None to indicate no matching user
    return None


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
connected_clientsz = {}
# Dictionary to map session keys to client sockets
client_sessions = {}

# When you want to send a message to all clients except the requester
def send_to_all_except_requester(message, requester_socket):
    for client_socket in connected_clients:
        if client_socket != requester_socket:
            client_socket.send(message)
            print(f"[broadcasted]: {message}")
"""
# Function to generate a random session ID and ensure it's unique
def generate_session_id():
    while True:
        session_id = random.randint(1, 999999)  # Adjust the range as needed
        if session_id not in used_session_ids:
            used_session_ids.append(session_id)
            return session_id
"""

def count_users():
    # Get the list of all user keys in Redis
    user_keys = redis_client.keys('Users:*')
    userscreated = 0
    # Iterate through user keys to find the highest session ID
    for user_key in user_keys:  
        userscreated += 1
    return userscreated

def generate_session_id():
    # Get the list of all user keys in Redis
    user_keys = redis_client.keys('Users:*')

    highest_session_id = 0

    # Iterate through user keys to find the highest session ID
    for user_key in user_keys:
        user_data = redis_client.hgetall(user_key)
        sesskey = user_data.get('sesskey')
        
        if sesskey is not None:
            sesskey = int(sesskey)
            if sesskey > highest_session_id:
                highest_session_id = sesskey

    # Increment the highest session ID by 1
    session_id = highest_session_id + 1
    return session_id

def generate_profile_id():
    # Get the list of all user keys in Redis
    user_keys = redis_client.keys('Profiles:*')

    highest_session_id = 0

    # Iterate through user keys to find the highest session ID
    for user_key in user_keys:
        user_data = redis_client.hgetall(user_key)
        sesskey = user_data.get('sesskey')
        
        if sesskey is not None:
            sesskey = int(sesskey)
            if sesskey > highest_session_id:
                highest_session_id = sesskey

    # Increment the highest session ID by 1
    session_id = highest_session_id + 1
    return session_id

desired_data_rate = 400 * 1024

def get_uniquenick_by_sesskey(sesskey_to_find):
    # Get all keys that match the pattern Users:*
    user_keys = redis_client.keys('Users:*')

    for user_key in user_keys:
        # Retrieve the user's data
        user_data = redis_client.hgetall(user_key)
        if user_data.get('sesskey') == sesskey_to_find:
            return user_data.get('uniquenick')  # Return the uniquenick

    return None  # Session key not found

def check_for_UUID(UUID_to_find):
    # Get all keys that match the pattern Users:*
    user_keys = redis_client.keys('Users:*')

    for user_key in user_keys:
        # Retrieve the user's data
        user_data = redis_client.hgetall(user_key)
        if user_data.get('uuid') == UUID_to_find:
            return user_data.get('uuid')  # Return the uniquenick

    return None

def generate_response(challenge, ac_challenge, secretkey, authtoken):
    """Generate a challenge response."""
    md5 = hashlib.md5()
    md5.update(ac_challenge)

    output = md5.hexdigest().encode('utf-8')  # Encode to bytes
    output += b' ' * 0x30  # Use 'b' to indicate bytes
    output += authtoken
    output += secretkey
    output += challenge
    output += md5.hexdigest().encode('utf-8')  # Encode to bytes

    md5_2 = hashlib.md5()
    md5_2.update(output)

    return md5_2.hexdigest()


def create_rand_string(length):
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" #string.ascii_uppercase
    return ''.join(random.choice(characters) for _ in range(length))

def create_rand_sig2(length):
    characters = "0123456789abcdef"
    sig = ''.join(random.choice(characters) for _ in range(length))
    return sig

def create_rand_lt():
    characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]["
    lt = ''.join(random.choice(characters) for _ in range(22))
    lt += "__"  # Append "__" to the generated string
    return lt

def create_rand_sig():
    characters = "0123456789abcdefghijklmnopqrstuvwxyz"
    sig = ''.join(random.choice(characters) for _ in range(32))
    return sig




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
            print(f"passenc matched: {password}")
            return passdec.decode(password)
        elif passwordenc_match:
            password = passwordenc_match.group(1)
            print(f"passwordenc matched: {password}")
            password = passenc_decode(password)
            return password
        elif password_match:
            password = password_match.group(1)
            print(f"password matched: {password}")
            return password
        else:
            return None
    except Exception as e:
        print(f"An error occurred on line {e.__traceback__.tb_lineno}: {e}")
        return None


def extract_values(data_received):
    try:
        data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string

        user = extract_uniquenick(data_str)
        if user:
            return None, user, None, None  # Return user information

        user = extract_user(data_str)
        if user:
            return None, user, None, None  # Return user information

        user = extract_nick(data_str)
        if user:
            return None, user, None, None  # Return user information

        authtoken = extract_authtoken(data_str)
        if authtoken:
            return None, authtoken, None, None  # Return authtoken information

        return None
    except Exception as e:
        print(f"An error occurred on line {e.__traceback__.tb_lineno}: {e}")
        return None

def kick_banned_user(banned_uniquenick , client_socket):
    banresponse = f"\\error\\\\err\\262\\fatal\\\\errmsg\\{banned_uniquenick} is banned From HeHeSPY.\\final\\"
    print(f"Sending ban response: {banresponse}")
    client_socket.send(banresponse.encode("utf-8"))
    client_socket.close()

def generate_lc_II_response(client_socket, data_received, first_conn, proof_built, GS_LT):
    try:
        data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string

        user_pattern = r'\\user\\([^\\]+)'
        uniquenick_pattern = r'\\uniquenick\\([^\\]+)'
        authtoken_pattern = r'\\authtoken\\([^\\]+)'

        user_match = re.search(user_pattern, data_str)
        uniquenick_match = re.search(uniquenick_pattern, data_str)
        authtoken_match = re.search(authtoken_pattern, data_str)

        print(f"user ban status: {usr_BANNED}")

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
        print(f"An error occurred on line {e.__traceback__.tb_lineno}: {e}")




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
        print(f"An error occurred on line {e.__traceback__.tb_lineno}: {e}")
        return None
    """
def do_md5(data):
    md5 = hashlib.md5()
    md5.update(data.encode('utf-8'))
    return md5.hexdigest()

def generate_proof(pid_user, user, data_received, client_socket):
    """
    Generate a challenge proof. [REDIS]

    The proof is practically the same thing as the response, except it has
    the challenge and the secret key swapped.
    """
    # Extract the client challenge from data_received
    client_chall_pattern = br'\\login\\\\challenge\\([^\\]+)'
    client_chall_match = re.search(client_chall_pattern, data_received)
    client_response_pattern = br'\\response\\([^\\]+)'
    client_response_match = re.search(client_response_pattern, data_received)

    if client_chall_match:
        client_chall = client_chall_match.group(1).decode('utf-8', errors='ignore')
        print(f"client chall: {client_chall}")
    else:
        print("Client challenge not found in received data.")
        return None

    # Attempt to retrieve the user's password from Redis based on the user's uniquenick
    try:
        global at_checkk
        global fixed_user
        if '@' in user:
            at_user = user
            at_checkk = True
            reslt = re.sub(r'@.*', '', user)
            print(f"found email in user, {reslt}")
            fixed_user = reslt
            user = reslt
            user_password = redis_client.hget(f'Users:{reslt}', 'password')
        else:
            at_checkk = False
            print("have not found email in user")
            user_password = redis_client.hget(f'Users:{user}', 'password')

    except redis.RedisError as e:
        print(f'Error retrieving password from Redis: {e}')
        user_password = None

    if user_password is None:
        print(f"User '{user}' not found in the database.")
        error_response = f"\\error\\\\err\\262\\fatal\\\\errmsg\\The profile {user} was not found in the database.\\id\\1\\final\\"
        print(f"SENDING ERROR: {error_response}")
        client_socket.send(error_response.encode("utf-8"))
        client_socket.close()
        return
    else:
        print(f"User '{user}' password retrieved from the database: {user_password}")
        if pass_enc:
            decrypted_passwdd = passenc_decode(user_password)
        else:
            decrypted_passwdd = user_password
        print(f"password: {decrypted_passwdd}")
    
    # Check if the user is banned
    user_banned = redis_client.hget(f'Users:{user}', 'banned')
    if user_banned == '1':
        # User is banned, send an error message
        banned_uniquenick = redis_client.hget(f'Users:{user}', 'uniquenick')
        print(f"User '{user}' is banned.")
        error_response = f"\\error\\\\err\\262\\fatal\\\\errmsg\\{banned_uniquenick} is banned From HeHeSPY.\\final\\"
        usr_BANNED = True
        kick_banned_user(user, client_socket)
    else:
        print(f"{user} passed ban checks!")
        usr_BANNED = False

    #if authtoken_req == False and partnerid != 0:
    #    user = f"{partnerid}@{user}"
    #else:
    #    user = f"{user}"

    pwd2md5 = do_md5(decrypted_passwdd)
    cRr = client_response_match.group(1)[:32]
    ccR = cRr.decode('utf-8')
    cR = ccR.replace("b'", "").replace("'", "")
    if partnerid != 0 or partnerid > 0:
        a_response = "{}{}{}{}{}{}".format(pwd2md5, " " * 48, pid_user, client_chall, server_chall, pwd2md5)
    else:
        if at_checkk == False:
            a_response = "{}{}{}{}{}{}".format(pwd2md5, " " * 48, user, client_chall, server_chall, pwd2md5)
        else:
            a_response = "{}{}{}{}{}{}".format(pwd2md5, " " * 48, at_user, client_chall, server_chall, pwd2md5)
    response = do_md5(a_response)
    print(f"Received RESPONSE: {cR}")
    print(f"Expected RESPONSE: {response}")

    if response.startswith(cR):
        Badpass = False
        print("Correct PASSWORD")
    else:
        Badpass = True
        print("BAD PASSWORD")
        error_response = "\\error\\\\err\\260\\fatal\\\\errmsg\\The password provided was incorrect.\\final\\"
        return error_response

    if not usr_BANNED or not Badpass:
        pwdmd5 = do_md5(decrypted_passwdd)
        print(f"USER:{user},CC:{client_chall},SC:{server_chall},pwd:{pwdmd5}")
        if partnerid != 0 or partnerid > 0:
            login_response = "{}{}{}{}{}{}".format(pwdmd5, " " * 48, pid_user, server_chall, client_chall, pwdmd5)
        else:
            if at_checkk == False:
                login_response = "{}{}{}{}{}{}".format(pwdmd5, " " * 48, user, server_chall, client_chall, pwdmd5)
            else:
                login_response = "{}{}{}{}{}{}".format(pwdmd5, " " * 48, at_user, server_chall, client_chall, pwdmd5)

        # buffer_str = pwdmd5 + ' ' * 48
        # buffer_str += user
        # buffer_str += server_chall
        # buffer_str += client_chall
        
            


        proof = do_md5(login_response)

        print(f"Proof Built: {proof}")
        return proof
    else:
        return error_response

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

    pwdmd5 = do_md5("RIPSPY")
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

def handle_friends_list(client_socket, cur_sesskey):
    # Get the list of all user keys in Redis
    user_keys = redis_client.keys('Users:*')

    # Iterate through user keys to find the highest session ID
    for user_key in user_keys:
        user_data = redis_client.hgetall(user_key)
        sesskey = user_data.get('sesskey')

        sesskey = int(sesskey)
        if cur_sesskey == 1:
            response = f"\\bm\\100\\f\\2\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0|qm|0\\final\\"
            print(f"Sending friend list: {response}")
            client_socket.send(response.encode("utf-8"))
        elif cur_sesskey == 2:
            response = f"\\bm\\100\\f\\1\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0|qm|0\\final\\"
            print(f"Sending friend list: {response}")
            client_socket.send(response.encode("utf-8"))

    return

"""
def handle_friends_list(client_socket, cur_sesskey):
    # Get the list of all user keys in Redis
    user_keys = redis_client.keys('Users:*')

    # Iterate through user keys to find the highest session ID
    for user_key in user_keys:
        user_data = redis_client.hgetall(user_key)
        sesskey = user_data.get('sesskey')

        if sesskey is not None and cur_sesskey is not None:
            sesskey = int(sesskey)
            response = f"\\bm\\100\\f\\{sesskey}\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0|qm|0\\final\\"
            print(f"Sending friend list: {response}")
            client_socket.send(response.encode("utf-8"))
            
            # Wait for the client's response (adjust the sleep duration as needed)
            response_received = client_socket.recv(1024)
            print(f"Received response: {response_received.decode('utf-8')}")

            # You can handle the response here if needed

            # Sleep to introduce a delay before sending the next message
            time.sleep(5)

    return
"""

def encrypt_data(data):
    # Encrypt the data
    encrypted_data = private_key.public_key().encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Print the encrypted data
    print("Encrypted Data:", encrypted_data)
    return encrypted_data

def decrypt_data(data):
    # Decrypt the data
    decrypted_data = private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Print the decrypted data
    print("Decrypted Data:", decrypted_data.decode('utf-8'))
    return decrypted_data.decode('utf-8')


class GPPartnerID(Enum):
    Gamespy = 0
    IGN = 10
    CryTek = 95

# Function to send data to a client identified by sess_key
def send_data_to_client(sess_key, data):
    if sess_key in client_sessions:
        client_socket = client_sessions[sess_key]
        try:
            # Send the data to the identified client
            client_socket.send(data)
            print(f"sending data to {sess_key}: {data}")
        except Exception as e:
            # Handle any errors that occur when sending
            print(f"Error sending data to {sess_key}: {e}")
    else:
        print(f"Client with sess_key {sess_key} not found.")

def initial_shit(client_socket):
    global server_chall
    server_chall = create_rand_string(10)
    response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
    print(f"Sending initial CHALLENGE: {response}")
    client_socket.send(response.encode("utf-8"))

def check_for_data(client_socket):
    # Use select to check if any of the sockets are readable
    readable, _, _ = select.select([client_socket], [], [], 0)

    # Check if any of the sockets are readable
    if client_socket in readable:
        # Data is available for reading on the client_socket
        print("Data is available for reading")
        # Now you can safely call recv() to receive the data
        data = client_socket.recv(1024)
        print("Received data length:", len(data))
        # Process the received data or handle it as needed
    else:
        initial_shit(client_socket)

def handle_client(client_socket, client_address, first_conn):
    global SESS_VAR    

    #check_for_data(client_socket)
    
    # Separate function to handle each client
    try:
        GS_LT = create_rand_lt()
        global server_chall
        server_chall = create_rand_string(10)
        #SESS_VAR = SESS_VAR = redis_client.hget(f'Users:{user}', 'sesskey')#get sesskey from user
      ###  #jses_counter += 1
        sesdo = urllib3.request(
    "POST",
    "http://127.0.0.1/api/sessionadded",
    headers={
        "X-Authorization": "HEYYOUSTOPTHERE"
    }
)
        print(sesdo.status)
        #client_socket.settimeout(10)
        #if client_address[0] != '127.0.0.1':
        #      print("Banned IP Joined")
        #      client_socket.close()
        ##response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
        ##print(len(client_socket.recv(1024)))
        ##print(f"Sending GS initial chall: {response}")
        ##client_socket.send(response.encode("utf-8"))
        #client_socket.settimeout(5)
        #response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
        #print(f"Sending GS initial chall: {response}")
        #client_socket.send(response.encode("utf-8"))        
        
        while True:            

            """
            if first_conn == True:
                GS_LT = create_rand_lt()
                global server_chall
                server_chall = create_rand_string(10)
                #SESS_VAR = SESS_VAR = redis_client.hget(f'Users:{user}', 'sesskey')#get sesskey from user
                # Respond with the initial challenge
                response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
                first_conn = False
            elif first_conn == False:
                pass
            """
            # Update last activity time
            connected_clientsz[client_socket]["last_activity_time"] = time.time()
                
            
            try:
                # Receive data from the client
                global data_received
                data_received = ""
                data_received = client_socket.recv(1024)
                global gdata_received
                gdata_received = data_received
                # Set flag to True after sending initial response
                connected_clientsz[client_socket]["responded"] = True
                

                """if data_received == "":
                    # Respond with the initial challenge
                    response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
                    print(f"Sending: {response}")
                    client_socket.send(response.encode("utf-8"))"""
            except socket.timeout:
                # Respond with the initial challenge
                #response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
                #print(f"Sending TIMEOUT CHALLENGE: {response}")
                #client_socket.send(response.encode("utf-8"))
                ...
                #client_socket.settimeout(None)
                
                
            if data_received == b"":
                response = f"\\lc\\1\\challenge\\{server_chall}\\"
                print(f"Sending TIMEOUT CHALLENGE: {response}")
                client_socket.send(response.encode("utf-8"))

            if not data_received:
                # No data received, client might have disconnected
                # Reset the first_conn flag for the next connection
                first_conn = True
                break  # Exit the loop when the client disconnects
            try:
                print(r"Received: {0}".format(data_received))
                #client_socket.settimeout(None)
            except Exception as e:
                print(f"main handle error: {e}")

            #if data_received == "":
            #    # Respond with the initial challenge
            #    response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
            #    print(f"Sending: {response}")
            #    client_socket.send(response.encode("utf-8"))

            if data_received.startswith(b"\\login\\"):
                data_str = data_received.decode('utf-8', errors='ignore')

                print("Building proof for login")
                authtoken_pattern = r'\\authtoken\\([^\\]+)'
                authtoken_match = re.search(authtoken_pattern, data_str)
                if authtoken_match:
                    authtoken_req = True
                    print(f"auth Tkn: {authtoken_req}")
                else:
                    authtoken_req = False
                    print(f"auth Tkn: {authtoken_req}")
                    

                partnerid_pattern = r'\\partnerid\\([^\\]+)'
                partnerid_match = re.search(partnerid_pattern, data_str)
                if partnerid_match:
                    localpid = partnerid_match.group(1)
                    global partnerid
                    partnerid = int(localpid)
                    int(partnerid)
                else:
                    partnerid = 0


                values = extract_values(data_received)  # Use data_received directly, which is binary
                if values:
                    password, user, dserver_chall, client_chall = values
                    if partnerid == GPPartnerID.Gamespy.value:
                        proof_built = generate_proof(None ,user, data_received, client_socket)  # Pass the original binary data
                        print("logging in normal")
                        print(f"auth Tkn: {authtoken_req}")
                        print("partner id was equal to 0")
                    else:
                        if authtoken_req == False:
                            proof_built = generate_proof(f"{partnerid}@{user}", user, data_received, client_socket)
                            print(f"logging in with Partnerid: {partnerid}")
                            print(f"auth Tkn: {authtoken_req}")
                        else:
                            proof_built = generate_proof(user, data_received, client_socket)  # Pass the original binary data
                            print("logging in normal")
                            print(f"auth Tkn: {authtoken_req}")
                        
                    #generate_lc_II_response(client_socket, data_received, first_conn, proof_built, GS_LT)
                    # Retrieve user data
                    user_data = get_user(user)
                    print(user_data)  # This will print the user's data as a dictionary
                    global SESS_VAR

                    if at_checkk:
                        SESS_VAR = redis_client.hget(f'Users:{fixed_user}', 'sesskey')#get sesskey from user
                        print(f"getting {SESS_VAR} from {fixed_user}")
                    else:
                        SESS_VAR = redis_client.hget(f'Users:{user}', 'sesskey')#get sesskey from user
                        print(f"getting {SESS_VAR} from {user}")


                    if at_checkk:
                        if usr_BANNED:
                            kick_banned_user(fixed_user, client_socket)
                        else:
                            generate_lc_II_response(client_socket, data_received, first_conn, proof_built, GS_LT)
                    else:
                        if usr_BANNED:
                            kick_banned_user(user, client_socket)
                        else:
                            generate_lc_II_response(client_socket, data_received, first_conn, proof_built, GS_LT)

                    print(f"{user} logged in with id {SESS_VAR}")

                    #response = f"\\lc\\2\\sesskey\\{SESS_VAR}\\proof\\{proof_built}\\userid\\{SESS_VAR}\\profileid\\{SESS_VAR}\\user\\{user}\\lt\\{GS_LT}\\id\\1\\final\\"
                    print(f"Sending: LC 2 response")


                    session_key = SESS_VAR  # Replace this with your logic to identify SESS_VAR
                    if session_key:
                        # Add the session key and client socket to the dictionary
                        client_sessions[session_key] = client_socket
                        print(f"client_sessions: {client_sessions}")
                    else:
                        print("Failed to identify session key")
                    
                    if at_checkk:
                        if redis_client.exists(f'Users:{fixed_user}'):
                            print("FOUND USER AND but not UPDATING SESSKEY")
                            #upd_user_sessid = {'sesskey': SESS_VAR,}
                            #redis_client.hmset(f'Users:{user}', upd_user_sessid)
                        else:
                            print("USER NOT FOUND and NOT UPDATING SESSKEY")
                    else:
                        if redis_client.exists(f'Users:{user}'):
                            print("FOUND USER AND but not UPDATING SESSKEY")
                            #upd_user_sessid = {'sesskey': SESS_VAR,}
                            #redis_client.hmset(f'Users:{user}', upd_user_sessid)
                        else:
                            print("USER NOT FOUND and NOT UPDATING SESSKEY")
                    
                    first_conn = False
                    #response2 = f"\\bm\\100\\f\\5\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0|qm|0\\final\\"
                    #print(f"Sending: {response2}")
                    #client_socket.send(response2.encode("utf-8"))
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
                if mkuser[1] == 'taken':
                    response = "\\error\\\\err\\513\\fatal\\\\errmsg\\Nick is taken.\\final\\"
                else:
                    response = f"\\nur\\\\pid\\{mkuser[0]}\\final\\"
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
            else:
                pass

            if data_received.startswith(b'\\bm\\1\\'):
                data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
                try:
                    bm_reason_pattern = r'\\msg\\([^\\]+)'
                    bm_reason_match = re.search(bm_reason_pattern, data_str)
                    bm_reason = bm_reason_match.group(1)
                except Exception:
                    bm_reason = ""

                bm_sender_pattern = r'\\sesskey\\([^\\]+)'
                bm_sender_match = re.search(bm_sender_pattern, data_str)
                bm_sender = bm_sender_match.group(1)

                bm_receiver_pattern = r'\\t\\([^\\]+)'
                bm_receiver_match = re.search(bm_receiver_pattern, data_str)
                bm_receiver = bm_receiver_match.group(1)

                #ab_response = f"\\bm\\1\\sesskey\\{bm_sender}\\t\\{bm_receiver}\\msg\\{bm_reason}\\final\\"
                ab_response = f"\\bm\\1\\f\\{bm_sender}\\date\\{int(time.time())}\\msg\\{bm_reason}\\final\\"
                #ab_response = f"\\bm\\1\\f\\{bm_sender}\\msg\\Hey there!  Would you like to become my friend?\\final\\"
                send_data_to_client(bm_receiver, ab_response.encode('utf-8'))
            else:
                pass

            if data_received.startswith(b'\\status\\'):
                data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
                sesskey_pattern = r'\\sesskey\\([^\\]+)'
                sesskey_match = re.search(sesskey_pattern, data_str)
                sesskey = sesskey_match.group(1)
                
                try:
                    locstring_pattern = r'\\locstring\\([^\\]+)'
                    locstring_match = re.search(locstring_pattern, data_str)
                    locstring = locstring_match.group(1)
                except Exception:
                    locstring = ""
                
                statstring_pattern = r'\\statstring\\([^\\]+)'
                statstring_match = re.search(statstring_pattern, data_str)
                statstring = statstring_match.group(1)
                
                #response = "\\msg\|s|1|ss|Online|ls|UK|ip|192.168.1.203|p|29900|qm|1\\final\\"
                #handle_status_request(client_socket, data_received)
                print("handling a status request")
                #response = "\\bm\\100\\f\\1\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0|qm|0\\final\\"
                response = f"\\bm\\100\\f\\{sesskey}\\msg\\|s|1|ss|{statstring}|ls|{locstring}|ip|0|p|0|qm|0\\final\\"
                #print(f"Sending: {response}")
                send_to_all_except_requester(response.encode("utf-8"), client_socket)
                #client_socket.send(response.encode("utf-8"))
                #handle_friends_list(client_socket, SESS_VAR)
            else:
                pass

            if data_received.startswith(b'\\registernick\\'):
                data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string

                # response to \\registernick\\\\sesskey\\1\\uniquenick\\kai\\partnerid\\95\\id\\3\\final\\
                partnerid_pattern = r'\\partnerid\\([^\\]+)'
                partnerid_match = re.search(partnerid_pattern, data_str)
                if partnerid_match:
                    localpid = partnerid_match.group(1)

                uniquenick_pattern = r'\\uniquenick\\([^\\]+)'
                uniquenick_match = re.search(uniquenick_pattern, data_str)
                if uniquenick_match:
                    localuniquenick = uniquenick_match.group(1)

                sesskey_pattern = r'\\sesskey\\([^\\]+)'
                sesskey_match = re.search(sesskey_pattern, data_str)
                if sesskey_match:
                    localsesskey = sesskey_match.group(1)

                user = id_to_user(localsesskey)
                update_user(user, 'uniquenick', localuniquenick)

                print("handling a registernick request")
                response = "\\rn\\\\id\\1\\final\\"
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
            else:
                pass

            #if data_received.startswith(b'\\addbuddy\\'):
            if b'\\addbuddy\\' in data_received:            
                data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
                try:
                    bm_reason_pattern = r'\\reason\\([^\\]+)'
                    bm_reason_match = re.search(bm_reason_pattern, data_str)
                    bm_reason = bm_reason_match.group(1)
                except Exception:
                    bm_reason = ""

                bm_sender_pattern = r'\\sesskey\\([^\\]+)'
                bm_sender_match = re.search(bm_sender_pattern, data_str)
                bm_sender = bm_sender_match.group(1)

                bm_receiver_pattern = r'\\newprofileid\\([^\\]+)'
                bm_receiver_match = re.search(bm_receiver_pattern, data_str)
                bm_receiver = bm_receiver_match.group(1)

                #ab_response = f"\\bm\\2\\f\\{bm_sender}\\msg\\{bm_reason}|signed|d41d8cd98f00b204e9800998ecf8427e\\final\\"
                ab_response = f"\\bm\\2\\f\\{bm_sender}\\msg\\{bm_reason}|signed|{create_rand_sig2(32)}\\final\\"                
                #ab_response = f"\\bm\\2\\f\\{bm_sender}\\msg\\Hey there!  Would you like to become my friend?\\final\\"
                send_data_to_client(bm_receiver, ab_response.encode('utf-8'))


               #response = f"\\bm\\2\\f\\2\\msg\\{bm_reason}\\"
                #response2 = "\\bm\\100\\f\\2\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0|qm|0\\final\\"
                #response = "\\error\\\\err\\\\fatal\\\\errmsg\\Failed to Send Friend req\\final\\"
                #print(f"Sending: {response}")
                #send_to_all_except_requester(response.encode('utf-8'), client_socket)
                #client_socket.send(response.encode("utf-8"))
                #send_to_all_except_requester(response, client_socket)
            else:
                pass

            if data_received.startswith(b'\\authadd\\'):
                data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
                bm_sig_pattern = r'\\sig\\([^\\]+)'
                bm_sig_match = re.search(bm_sig_pattern, data_str)
                bm_sig = bm_sig_match.group(1)

                bm_sender_pattern = r'\\sesskey\\([^\\]+)'
                bm_sender_match = re.search(bm_sender_pattern, data_str)
                bm_sender = bm_sender_match.group(1)

                bm_receiver_pattern = r'\\fromprofileid\\([^\\]+)'
                bm_receiver_match = re.search(bm_receiver_pattern, data_str)
                bm_receiver = bm_receiver_match.group(1)

                #ab_response = f"\\bm\\3\\f\\{bm_sender}\\msg\\I have authorized your request to add me to your list|signed|d41d8cd98f00b204e9800998ecf8427e\\final\\"

                bdylist = f"\\bm\\100\\f\\{bm_receiver}\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!HeHeSPY/?type=title|ip|0|p|0|qm|0\\final\\"
                client_socket.send(bdylist.encode('utf-8'))
                ab_response = f"\\bm\\4\\f\\{bm_sender}\\msg\\I have authorized your request to add me to your list|signed|{bm_sig}\\final\\"  # dont know anymore
                abr_response = f"\\bm\\4\\f\\{bm_receiver}\\msg\\I have authorized your request to add me to your list|signed|{bm_sig}\\final\\"  # dont know anymore
                #ab_response = f"\\bm\\100\\f\\{bm_sender}\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0|qm|0\\final\\"
                send_data_to_client(bm_receiver, ab_response.encode('utf-8'))
                send_data_to_client(bm_sender, abr_response.encode('utf-8'))


               #response = f"\\bm\\2\\f\\2\\msg\\{bm_reason}\\"
                #response2 = "\\bm\\100\\f\\2\\msg\\|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0|qm|0\\final\\"
                #response = "\\error\\\\err\\\\fatal\\\\errmsg\\Failed to Send Friend req\\final\\"
                #print(f"Sending: {response}")
                #send_to_all_except_requester(response.encode('utf-8'), client_socket)
                #client_socket.send(response.encode("utf-8"))
                #send_to_all_except_requester(response, client_socket)
            else:
                pass

            if data_received.startswith(b"\\logout\\"):
                print("client logging out")
                if session_key in client_sessions:
                    client_sessions[session_key].close()
                    del client_sessions[session_key]
                #response = "\\error\\\\err\\259\\fatal\\\\errmsg\\logging out!\\final\\"
                #first_conn = True
                #print(f"Sending: {response}")
                #client_socket.send(response.encode("utf-8"))
                client_socket.close()
            else:
                pass

            #if data_received.startswith(b"\\getprofile\\"):
            if b"\\getprofile\\" in data_received:
                data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
                #bm_sessky_pattern = r'\\sesskey\\([^\\]+)'
                bm_sessky_pattern = r'\\profileid\\([^\\]+)'
                bm_sessky_match = re.search(bm_sessky_pattern, data_str)
                bm_sessky = bm_sessky_match.group(1)

                req_id_pattern = r'\\id\\([^\\]+)'
                req_id_match = re.search(req_id_pattern, data_str)
                req_id = req_id_match.group(1)

                bm_sk_nick = get_uniquenick_by_sesskey(bm_sessky)
                bm_sk_email = user_to_email(bm_sk_nick)
                firstname = get_names_by_sesskey(bm_sessky)[0]
                lastname = get_names_by_sesskey(bm_sessky)[1]

                print("client asking for profile")
                #\sig\ cf35a2e4b94b109c77f3d6018de435aa length [32]
                gs_sig = create_rand_sig2(32)#"d41d8cd98f00b204e9800998ecf8427e" #create_rand_sig()
                response = f"\\pi\\\\profileid\\{bm_sessky}\\nick\\{bm_sk_nick}\\userid\\{bm_sessky}\\email\\{bm_sk_email}\\sig\\{gs_sig}\\uniquenick\\{bm_sk_nick}\\pid\\{bm_sessky}\\firstname\\{firstname}\\lastname\\{lastname}\\homepage\\thexgamelord.uk.to\\zipcode\\00000\\countrycode\\UK\\st\\  \\birthday\\0\\sex\\0\\icquin\\0\\aim\\\\pic\\0\\publicmask\\64\\occ\\0\\ind\\0\\inc\\0\\mar\\0\\chc\\0\\i1\\0\\o1\\0\\mp\\4\\lon\\0.000000\\lat\\0.000000\\loc\\\\conn\\1\\id\\{req_id}\\final\\"
                #response = f"\\pi\\\\profileid\\{SESS_VAR}\\nick\\{username}\\uniquenick\\{SESS_VAR}\\email\\{usr_email}\\firstname\\HeHeSPY\\lastname\\HeHeSPY\\icquin\\0\\homepage\\https://thexgamelord.uk.to/\\zipcode\\NG0000\\countrycode\\US\\lon\\0.000000\\lat\\0.000000\\loc\\\\birthday\\0\\sex\\0\\pmask\\64\\aim\\{username}\\pic\\0\\occ\\0\\ind\\0\\inc\\0\\mar\\0\\chc\\0\\i1\\0\\o1\\0\\conn\\1\\sig\\{gs_sig}\\id\\2\\final\\"
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
                pass
            else:
                pass

            if data_received.startswith(b'\\msg\\\\final\\'):
                # Respond with PONG to PING
                response = "\\msg\\1\\final\\"
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
            else:
                pass
            
            if data_received.startswith(b'\\ka\\\\final\\'):
                # Respond with the initial challenge
                response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
                print(f"Sending ka initial resp: {response}")
                client_socket.send(response.encode("utf-8"))
            else:
                pass

            if data_received.startswith(b'\\kickall\\'):
                data_str = data_received.decode('utf-8', errors='ignore')  # Decode the received bytes to a string
                heheSPya4th_pattern = r'\\auth\\([^\\]+)'
                heheSPya4th_match = re.search(heheSPya4th_pattern, data_str)
                heheSPya4th = heheSPya4th_match.group(1)

                heheSPya4tha = heheSPya4th.replace("3h3H", "").replace("h3FrIP", "")
                if heheSPya4tha == "f69fc2ba27226e3be60c03bb69747985":
                    print("kickall received")
                    disconnect()
                else:
                    print("wrong authorization")
            else:
                pass

            if data_received.startswith(b'GET / HTTP'):
                # Respond to http request
                response2 = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>503 Service Unavailable</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            color: #333;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .container {
            text-align: center;
        }

        h1 {
            color: #d9534f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>503 Service Unavailable</h1>
        <p>Sorry, this server is not ready for normal browsers at the moment. This will be added later.</p>
    </div>
</body>
</html>
                '''

                response1 = f'''HTTP/1.1 503 Service Unavailable
Content-Type: text/html; charset=utf-8
Content-Length: {len(response2)};
X-Organisation: Thexgamelord;
'''                

                response3 = response1+response2
                print(f"Sending: {response3}")
                client_socket.send(response3.encode("utf-8"))
                client_socket.close()
            else:
                pass

            if data_received.startswith(b'HEAD / HTTP'):
                # Respond to http HEAD request
                response2 = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>503 Service Unavailable</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            color: #333;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .container {
            text-align: center;
        }

        h1 {
            color: #d9534f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>503 Service Unavailable</h1>
        <p>Sorry, this server is not ready for normal browsers at the moment. This will be added later.</p>
    </div>
</body>
</html>
                '''

                response1 = f'''HTTP/1.1 503 Service Unavailable;
Content-Type: text/html; charset=utf-8
Content-Length: {len(response2)};
X-Organisation: Thexgamelord;
'''                

                response3 = response1+response2
                print(f"Sending: {response3}")
                client_socket.send(response3.encode("utf-8"))
                client_socket.close()
            else:
                pass


            if data_received.startswith(b'\x16\x03\x01'):
                # Close HTTPS requests
                client_socket.close()
            else:
                pass

            if data_received.startswith(b'\\inviteto\\'):
                #response = "\\msg\|s|1|ss|Online|ls|UK|ip|192.168.1.203|p|29900|qm|1\\final\\"
                #handle_status_request(client_socket, data_received)
                print("handling a inviteto request")
                #response = "\\pinvite\\\\sesskey\\223\\profileid\\13\\productid\\1038\\final\\"
                #print(f"Sending: {response}")
                #client_socket.send(response.encode("utf-8"))
                response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
                print(f"Sending GS inviteto chall: {response}")
                client_socket.send(response.encode("utf-8"))
                #client_socket.close()
            else:
                pass
                
            if data_received.startswith(b'\\updatepro\\'):
                print("handling a updatepro request")
                response = "\\error\\\\err\\1280\\fatal\\\\errmsg\\There was an error updating the profile information.\\id\\1\\final\\"
                print(f"Sending: {response}")
                client_socket.send(response.encode("utf-8"))
            else:
                pass
            
            if data_received.startswith(b'testenc'):
                # Respond with PONG to PING
                response = encrypt_data(b"This is my encryption testing using a private key to encrypt data for a possible Proxy to forward game data without leaking information to a man in the middle attack.")
                decrypt_data(response)
                print(f"Sending: {response}")
                client_socket.send(base64.b64encode(response))
            else:
                pass
                
            if data_received.startswith(b'GET /info.json HTTP'):
                # Respond to http request
                users = {'id': 1, 'username': 'sweety'}
                response2 = f"{json.dumps(users)}"

                response1 = f'''HTTP/1.1 200 OK;
Content-Type: text/json; charset=utf-8
Content-Length: {len(response2)};
'''                

                response3 = response1+response2
                print(f"Sending: {response3}")
                client_socket.send(response3.encode("utf-8"))
                client_socket.close()
            else:
                pass
                
                
            # ... Handle other cases like status, getprofile, newuser ...

    except Exception as ex:
        # Handle any exceptions
        print(f"An error occurred on line {ex.__traceback__.tb_lineno}: {ex}")
        #first_conn = True
    finally:
        # Close the client socket
        client_socket.close()
        if client_socket in connected_clients:
            connected_clients.remove(client_socket)
        if client_socket in connected_clientsz:
            del connected_clientsz[client_socket]
        try:
            if session_key in client_sessions:
                client_sessions[session_key].close()
                del client_sessions[session_key]
        except Exception:
            print("error on session key kicking")
        print(f"[-] client removed: {client_address[0]}")
        Badpass = False
        #first_conn = True
        print("Client disconnected.")
      ###  jses_counter -= 1
        sesundo = urllib3.request(
    "POST",
    "http://127.0.0.1/api/sessionremoved",
    headers={
        "X-Authorization": "HEYYOUSTOPTHERE"
    }
)
        print(sesundo.status)

# Function to send keep-alive messages to all connected clients
def send_keep_alive():
    while True:
        for client_socket in connected_clients:
            try:
                # Send the keep-alive message to the client
                keep_alive_message = b"\\ka\\final\\"
                client_socket.send(keep_alive_message.encode("utf-8"))
            except Exception as e:
                # Handle any errors that occur when sending
                print(f"Error sending keep-alive message: {e}")

        # Adjust the sleep duration to control the frequency of keep-alive messages
        time.sleep(30)  # Sends keep-alive every 30 seconds

def disconnect():
    discresponse = "\\error\\\\err\\259\\fatal\\\\errmsg\\kicked by admin!\\final\\"
    all_client_sockets.send(discresponse.encode('utf-8'))
    all_client_sockets.close()
    print("[ADMIN] KICKING ALL CLIENTS")

"""def status_loop():
    while True:
        sheaders = {
        'GS-AUTH': 'testing'
        }   
        print("Updating server status")
        sreq = requests.post("http://192.168.1.203:5000/api/gpcm", headers=sheaders)
        print(f"status: {sreq.status_code}")
        time.sleep(120)"""
   

def monitor_inactivity():
    while True:
        # Iterate over connected clients
        for client_socket, client_info in connected_clientsz.items():
            last_activity_time = client_info["last_activity_time"]
            is_responded = client_info["responded"]
            #print(is_responded)
            # Check if the client has been inactive for more than x seconds
            if time.time() - last_activity_time > random.uniform(10, 15) and is_responded == False:
                response = f"\\lc\\1\\challenge\\{server_chall}\\id\\1\\final\\"
                print(f"Sending GS initial chall: {response}")
                client_socket.send(response.encode("utf-8"))   
        time.sleep(1)  # Check every second for inactivity


def main():
    host = "0.0.0.0"
    port = 29900
    global first_conn
    first_conn = True
    #global G_sig
    #G_sig = create_rand_sig()

    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Bind the socket to the host and port
        server_socket.bind((host, port))

        # Start listening for incoming connections
        server_socket.listen()
        
        print(f"Server is listening on {host}:{port}")
        
        # Start the monitor_inactivity thread
        threading.Thread(target=monitor_inactivity).start()        

        while True:
            global start_time
            start_time = time.time()            
            
            # Accept an incoming client connection#
            global all_client_sockets            
            client_socket, client_address = server_socket.accept()   
            ### IP BANNING SYSTEM
            banned_ips = ["127.1.1.0"]            
            all_client_sockets = client_socket
            if client_address[0] in banned_ips:
                print("Banned IP Joined")
                ip_address_parts = client_address[0].split('.')
                masked_address = '.'.join(ip_address_parts[:-3] + ['xxx', 'xxx', 'xxx'])
                client_socket.send(b'\\error\\\\err\\263\\fatal\\\\errmsg\\The server has refused the connection because your IP ADDRESS ' + bytes(masked_address, 'utf-8') + b' is banned.\\final\\')
                client_socket.close()
            else:
                print("ACCESS GRANTED")
                print(f"Client connected from {client_address[0]}:{client_address[1]}")
                first_conn = True
                # Add this line to add a connected client's socket to the list
                connected_clients.append(client_socket)
                # Add the client socket to the dictionary of connected clients
                connected_clientsz[client_socket] = {"address": client_address, "last_activity_time": time.time(), "responded": False}
                print(f"[+] new client added: {client_address[0]}")     
                
                # Start a new thread to handle the client
                client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address, first_conn))
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