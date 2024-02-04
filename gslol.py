import hashlib
import sys

def do_md5(data):
    md5 = hashlib.md5()
    md5.update(data.encode('utf-8'))
    return md5.hexdigest()

if len(sys.argv) < 5:
    print("Usage: {} <nickname[@email]> <password> <client_challenge> <server_challenge>".format(sys.argv[0]))
    sys.exit(1)

nickname = sys.argv[1]
password = sys.argv[2]
client_challenge = sys.argv[3]
server_challenge = sys.argv[4]

pwdmd5 = do_md5(password)

login_response = "{}{}{}{}{}{}".format(
    pwdmd5,
    " " * 48,
    nickname,
    client_challenge,
    server_challenge,
    pwdmd5
)
print(f"USER:{nickname},CC:{client_challenge},SC:{server_challenge},pwd:{pwdmd5}")
response_md5 = do_md5(login_response)

print("- response: {}".format(response_md5))
