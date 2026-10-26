
from flask import Flask, render_template, request
import os

app = Flask(__name__)
key = os.urandom(16)


def base64_encode(data):
    if isinstance(data, str):
        data = data.encode()

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    result = ""

    for i in range(0, len(data), 3):
        b = data[i]
        c = data[i + 1] if i + 1 < len(data) else 0
        d = data[i + 2] if i + 2 < len(data) else 0
        n = (b << 16) | (c << 8) | d

        result += alphabet[(n >> 18) & 63]
        result += alphabet[(n >> 12) & 63]
        result += alphabet[(n >> 6) & 63] if i + 1 < len(data) else "="
        result += alphabet[n & 63] if i + 2 < len(data) else "="

    return result


def gf_mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 256:
            a ^= 0x11B
        b >>= 1
    return result


def rotate_byte(x, n):
    return ((x << n) | (x >> (8 - n))) & 255


def make_sbox():
    box = []
    for x in range(256):
        inv = 0
        if x:
            inv, base, power = 1, x, 254
            while power:
                if power & 1:
                    inv = gf_mul(inv, base)
                base = gf_mul(base, base)
                power >>= 1
        box.append(
            inv ^ rotate_byte(inv, 1) ^ rotate_byte(inv, 2)
            ^ rotate_byte(inv, 3) ^ rotate_byte(inv, 4) ^ 0x63
        )
    return box


SBOX = make_sbox()


def expand_key(key):
    expanded = list(key)
    rcon = 1

    while len(expanded) < 176:
        temp = expanded[-4:]

        if len(expanded) % 16 == 0:
            temp = [SBOX[x] for x in temp[1:] + temp[:1]]
            temp[0] ^= rcon
            rcon = gf_mul(rcon, 2)

        for x in temp:
            expanded.append(expanded[-16] ^ x)

    return expanded


def add_round_key(state, key_part):
    for i in range(16):
        state[i] ^= key_part[i]


def sub_bytes(state):
    for i in range(16):
        state[i] = SBOX[state[i]]


def shift_rows(state):
    old = state[:]
    for r in range(4):
        for c in range(4):
            state[r + 4 * c] = old[r + 4 * ((c + r) % 4)]


def mix_columns(state):
    for c in range(4):
        i = c * 4
        a, b, d, e = state[i:i + 4]
        state[i] = gf_mul(a, 2) ^ gf_mul(b, 3) ^ d ^ e
        state[i + 1] = a ^ gf_mul(b, 2) ^ gf_mul(d, 3) ^ e
        state[i + 2] = a ^ b ^ gf_mul(d, 2) ^ gf_mul(e, 3)
        state[i + 3] = gf_mul(a, 3) ^ b ^ d ^ gf_mul(e, 2)


def aes_encrypt_block(block, expanded_key):
    state = list(block)
    add_round_key(state, expanded_key[:16])

    for r in range(1, 11):
        sub_bytes(state)
        shift_rows(state)
        if r != 10:
            mix_columns(state)
        add_round_key(state, expanded_key[r * 16:(r + 1) * 16])

    return bytes(state)


def encrypt_data(message):
    if isinstance(message, str):
        message = message.encode()

    iv = os.urandom(16)
    expanded_key = expand_key(key)
    pad = 16 - len(message) % 16
    message += bytes([pad] * pad)

    result = b""
    previous = iv

    for i in range(0, len(message), 16):
        block = bytes(a ^ b for a, b in zip(message[i:i + 16], previous))
        previous = aes_encrypt_block(block, expanded_key)
        result += previous

    return iv + result


SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
]

SHA256_INITIAL = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
]


def right_rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def generate_hash(message):
    if isinstance(message, str):
        message = message.encode()

    length = len(message) * 8
    message += b"\x80"

    while len(message) % 64 != 56:
        message += b"\x00"

    message += length.to_bytes(8, "big")
    h = SHA256_INITIAL[:]

    for offset in range(0, len(message), 64):
        block = message[offset:offset + 64]
        w = [
            int.from_bytes(block[i:i + 4], "big")
            for i in range(0, 64, 4)
        ]

        for i in range(16, 64):
            s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, hh = h

        for i in range(64):
            s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            choice = (e & f) ^ (~e & g)
            t1 = (hh + s1 + choice + SHA256_K[i] + w[i]) & 0xFFFFFFFF

            s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            t2 = (s0 + majority) & 0xFFFFFFFF

            hh, g, f = g, f, e
            e = (d + t1) & 0xFFFFFFFF
            d, c, b = c, b, a
            a = (t1 + t2) & 0xFFFFFFFF

        values = [a, b, c, d, e, f, g, hh]
        for i in range(8):
            h[i] = (h[i] + values[i]) & 0xFFFFFFFF

    return "".join(format(x, "08x") for x in h)


@app.route("/", methods=["GET", "POST"])
def index():
    original_message = ""
    encoded_message = ""
    encrypted_message = ""
    hash_value = ""

    if request.method == "POST":
        original_message = request.form.get("message", "")

        if original_message.strip():
            encoded_message = base64_encode(original_message)
            encrypted_message = base64_encode(encrypt_data(encoded_message))
            hash_value = generate_hash(encoded_message)

    return render_template(
        "index.html",
        original_message=original_message,
        encoded_message=encoded_message,
        encrypted_message=encrypted_message,
        hash_value=hash_value
    )


if __name__ == "__main__":
    app.run(debug=True)
