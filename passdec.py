import base64

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

def decode(password):
    decoded_password = Gdecode(password)
    return decoded_password
