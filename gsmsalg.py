def gsvalfunc(reg):
    if reg < 26:
        return chr(reg + ord('A'))
    if reg < 52:
        return chr(reg - 26 + ord('a'))
    if reg < 62:
        return chr(reg - 52 + ord('0'))
    if reg == 62:
        return '+'
    if reg == 63:
        return '/'
    return '\x00'

def gsseckey(dst, src, key, enctype):
    size = len(src)
    if not dst:
        dst = bytearray(89)
    if not src or size < 1 or size > 65:
        dst[0] = 0
        return dst

    keysz = len(key)
    enctmp = bytearray(range(256))

    a = 0
    for i in range(256):
        a = (a + enctmp[i] + ord(key[i % keysz])) & 0xFF
        x = enctmp[a]
        enctmp[a] = enctmp[i]
        enctmp[i] = x

    a = 0
    b = 0
    tmp = bytearray(66)
    for i in range(size):
        a = (a + ord(src[i]) + 1) & 0xFF
        x = enctmp[a]
        b = (b + x) & 0xFF
        y = enctmp[b]
        enctmp[b] = x
        enctmp[a] = y
        tmp[i] = src[i] ^ enctmp[(x + y) & 0xFF]

    while size % 3:
        tmp[size] = 0
        size += 1

    if enctype == 1:
        for i in range(size):
            tmp[i] = bytearray(b'\x01\xba\xfa\xb2\x51\x00\x54\x80\x75\x16\x8e\x8e\x02\x08\x36\xa5'
                                b'\x2d\x05\x0d\x16\x52\x07\xb4\x22\x8c\xe9\x09\xd6\xb9\x26\x00\x04'
                                b'\x06\x05\x00\x13\x18\xc4\x1e\x5b\x1d\x76\x74\xfc\x50\x51\x06\x16'
                                b'\x00\x51\x28\x00\x04\x0a\x29\x78\x51\x00\x01\x11\x52\x16\x06\x4a'
                                b'\x20\x84\x01\xa2\x1e\x16\x47\x16\x32\x51\x9a\xc4\x03\x2a\x73\xe1'
                                b'\x2d\x4f\x18\x4b\x93\x4c\x0f\x39\x0a\x00\x04\xc0\x12\x0c\x9a\x5e'
                                b'\x02\xb3\x18\xb8\x07\x0c\xcd\x21\x05\xc0\xa9\x41\x43\x04\x3c\x52'
                                b'\x75\xec\x98\x80\x1d\x08\x02\x1d\x58\x84\x01\x4e\x3b\x6a\x53\x7a'
                                b'\x55\x56\x57\x1e\x7f\xec\xb8\xad\x00\x70\x1f\x82\xd8\xfc\x97\x8b'
                                b'\xf0\x83\xfe\x0e\x76\x03\xbe\x39\x29\x77\x30\xe0\x2b\xff\xb7\x9e'
                                b'\x01\x04\xf8\x01\x0e\xe8\x53\xff\x94\x0c\xb2\x45\x9e\x0a\xc7\x06'
                                b'\x18\x01\x64\xb0\x03\x98\x01\xeb\x02\xb0\x01\xb4\x12\x49\x07\x1f'
                                b'\x5f\x5e\x5d\xa0\x4f\x5b\xa0\x5a\x59\x58\xcf\x52\x54\xd0\xb8\x34'
                                b'\x02\xfc\x0e\x42\x29\xb8\xda\x00\xba\xb1\xf0\x12\xfd\x23\xae\xb6'
                                b'\x45\xa9\xbb\x06\xb8\x88\x14\x24\xa9\x00\x14\xcb\x24\x12\xae\xcc'
                                b'\x57\x56\xee\xfd\x08\x30\xd9\xfd\x8b\x3e\x0a\x84\x46\xfa\x77\xb8'
                                )[tmp[i]]

    elif enctype == 2:
        for i in range(size):
            tmp[i] ^= ord(key[i % keysz])

    p = 0
    for i in range(0, size, 3):
        x = tmp[i]
        y = tmp[i + 1]
        z = tmp[i + 2]
        dst[p] = gsvalfunc(x >> 2)
        dst[p + 1] = gsvalfunc(((x & 3) << 4) | (y >> 4))
        dst[p + 2] = gsvalfunc(((y & 15) << 2) | (z >> 6))
        dst[p + 3] = gsvalfunc(z & 63)
        p += 4
    dst[p] = 0

    return dst