import os

MAGIC = b'SES4'
LEGACY_MAGIC = b'SES3'
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ROUNDS = 100
LEGACY_PBKDF2_ROUNDS = 2000
TAG_SIZE = 32
ROUND_SIZE = 4
AES_BLOCK_SIZE = 16
AES_ROUNDS = 14
_SHA256_BLOCK_SIZE = 64
_SHA256_OUTPUT_SIZE = 32

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

_RCON = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000,
    0x36000000,
]

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


def _rotr32(value, shift):
    return (value >> shift) | ((value << (32 - shift)) & 0xffffffff)


def _sha256(data):
    bit_length = (len(data) * 8).to_bytes(8, 'big')
    data = data + b'\x80'
    data += b'\x00' * ((56 - len(data) % 64) % 64)
    data += bit_length
    hash_words = _H0[:]

    for offset in range(0, len(data), 64):
        block = data[offset:offset + 64]
        schedule = [int.from_bytes(block[i:i + 4], 'big') for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = _rotr32(schedule[i - 15], 7) ^ _rotr32(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3)
            s1 = _rotr32(schedule[i - 2], 17) ^ _rotr32(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10)
            schedule.append((schedule[i - 16] + s0 + schedule[i - 7] + s1) & 0xffffffff)

        a, b, c, d, e, f, g, h = hash_words
        for i in range(64):
            big_s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
            choose = (e & f) ^ ((~e) & g)
            temp1 = (h + big_s1 + choose + _K[i] + schedule[i]) & 0xffffffff
            big_s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (big_s0 + majority) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        compressed = [a, b, c, d, e, f, g, h]
        hash_words = [(hash_words[i] + compressed[i]) & 0xffffffff for i in range(8)]

    return b''.join(word.to_bytes(4, 'big') for word in hash_words)


def _constant_time_equal(left, right):
    if len(left) != len(right):
        return False
    result = 0
    for first, second in zip(left, right):
        result |= first ^ second
    return result == 0


def _hmac_sha256(key, message):
    if len(key) > _SHA256_BLOCK_SIZE:
        key = _sha256(key)
    key = key + b'\x00' * (_SHA256_BLOCK_SIZE - len(key))
    outer_key = bytes(byte ^ 0x5c for byte in key)
    inner_key = bytes(byte ^ 0x36 for byte in key)
    return _sha256(outer_key + _sha256(inner_key + message))


def _pbkdf2_hmac_sha256(password, salt, rounds, output_length):
    blocks = []
    block_count = (output_length + _SHA256_OUTPUT_SIZE - 1) // _SHA256_OUTPUT_SIZE
    for block_index in range(1, block_count + 1):
        previous = _hmac_sha256(password, salt + block_index.to_bytes(4, 'big'))
        result = bytearray(previous)
        for _ in range(1, rounds):
            previous = _hmac_sha256(password, previous)
            for index, byte in enumerate(previous):
                result[index] ^= byte
        blocks.append(bytes(result))
    return b''.join(blocks)[:output_length]


def _derive_keys(passphrase, salt, rounds):
    password = passphrase.encode('utf-8')
    material = _pbkdf2_hmac_sha256(password, salt, rounds, KEY_SIZE * 2)
    return material[:KEY_SIZE], material[KEY_SIZE:]


def _sub_word(word):
    return (
        (_SBOX[(word >> 24) & 0xff] << 24)
        | (_SBOX[(word >> 16) & 0xff] << 16)
        | (_SBOX[(word >> 8) & 0xff] << 8)
        | _SBOX[word & 0xff]
    )


def _rot_word(word):
    return ((word << 8) & 0xffffffff) | (word >> 24)


def _expand_aes256_key(key):
    if len(key) != KEY_SIZE:
        raise ValueError('AES-256 requires a 32-byte key.')
    words = [int.from_bytes(key[index:index + 4], 'big') for index in range(0, KEY_SIZE, 4)]
    for index in range(8, 4 * (AES_ROUNDS + 1)):
        temp = words[index - 1]
        if index % 8 == 0:
            temp = _sub_word(_rot_word(temp)) ^ _RCON[index // 8]
        elif index % 8 == 4:
            temp = _sub_word(temp)
        words.append(words[index - 8] ^ temp)
    return [b''.join(words[index + offset].to_bytes(4, 'big') for offset in range(4)) for index in range(0, len(words), 4)]


def _add_round_key(state, round_key):
    for index, byte in enumerate(round_key):
        state[index] ^= byte


def _sub_bytes(state):
    for index, byte in enumerate(state):
        state[index] = _SBOX[byte]


def _shift_rows(state):
    original = state[:]
    for row in range(4):
        for col in range(4):
            state[row + 4 * col] = original[row + 4 * ((col + row) % 4)]


def _xtime(byte):
    byte <<= 1
    if byte & 0x100:
        byte ^= 0x11b
    return byte & 0xff


def _mix_single_column(state, col):
    base = 4 * col
    a0, a1, a2, a3 = state[base:base + 4]
    t = a0 ^ a1 ^ a2 ^ a3
    u = a0
    state[base] ^= t ^ _xtime(a0 ^ a1)
    state[base + 1] ^= t ^ _xtime(a1 ^ a2)
    state[base + 2] ^= t ^ _xtime(a2 ^ a3)
    state[base + 3] ^= t ^ _xtime(a3 ^ u)


def _mix_columns(state):
    for col in range(4):
        _mix_single_column(state, col)


def _aes_encrypt_block(block, round_keys):
    if len(block) != AES_BLOCK_SIZE:
        raise ValueError('AES block encryption requires exactly 16 bytes.')
    state = bytearray(block)
    _add_round_key(state, round_keys[0])
    for round_index in range(1, AES_ROUNDS):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_index])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[AES_ROUNDS])
    return bytes(state)


def _aes_ctr_xor(data, key, nonce):
    round_keys = _expand_aes256_key(key)
    output = bytearray()
    counter = 0
    for offset in range(0, len(data), AES_BLOCK_SIZE):
        counter_block = nonce + counter.to_bytes(4, 'big')
        block = _aes_encrypt_block(counter_block, round_keys)
        chunk = data[offset:offset + AES_BLOCK_SIZE]
        output.extend(byte ^ block[index] for index, byte in enumerate(chunk))
        counter += 1
        if counter > 0xffffffff:
            raise ValueError('File is too large for one encryption stream.')
    return bytes(output)


def encrypt_file(file_data, passphrase):
    if not passphrase:
        raise ValueError('A passphrase is required for encryption.')
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    enc_key, mac_key = _derive_keys(passphrase, salt, PBKDF2_ROUNDS)
    ciphertext = _aes_ctr_xor(file_data, enc_key, nonce)
    header = MAGIC + PBKDF2_ROUNDS.to_bytes(ROUND_SIZE, 'big') + salt + nonce
    tag = _hmac_sha256(mac_key, header + ciphertext)
    return header + ciphertext + tag


def decrypt_file(encrypted_data, passphrase):
    if not passphrase:
        raise ValueError('A passphrase is required for decryption.')
    legacy_min_size = len(LEGACY_MAGIC) + SALT_SIZE + NONCE_SIZE + TAG_SIZE
    current_min_size = len(MAGIC) + ROUND_SIZE + SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if encrypted_data.startswith(MAGIC):
        if len(encrypted_data) < current_min_size:
            raise ValueError('Unsupported encrypted file format.')
        round_start = len(MAGIC)
        salt_start = round_start + ROUND_SIZE
        rounds = int.from_bytes(encrypted_data[round_start:salt_start], 'big')
        if rounds <= 0:
            raise ValueError('Unsupported encrypted file format.')
    elif encrypted_data.startswith(LEGACY_MAGIC):
        if len(encrypted_data) < legacy_min_size:
            raise ValueError('Unsupported encrypted file format.')
        salt_start = len(LEGACY_MAGIC)
        rounds = LEGACY_PBKDF2_ROUNDS
    else:
        raise ValueError('Unsupported encrypted file format.')
    nonce_start = salt_start + SALT_SIZE
    data_start = nonce_start + NONCE_SIZE
    tag_start = len(encrypted_data) - TAG_SIZE
    salt = encrypted_data[salt_start:nonce_start]
    nonce = encrypted_data[nonce_start:data_start]
    ciphertext = encrypted_data[data_start:tag_start]
    supplied_tag = encrypted_data[tag_start:]
    enc_key, mac_key = _derive_keys(passphrase, salt, rounds)
    expected_tag = _hmac_sha256(mac_key, encrypted_data[:tag_start])
    if not _constant_time_equal(supplied_tag, expected_tag):
        raise ValueError('Wrong passphrase or file has been changed.')
    return _aes_ctr_xor(ciphertext, enc_key, nonce)

