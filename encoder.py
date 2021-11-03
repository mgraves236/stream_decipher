# Program to encode a txt file with a given key with a stream cipher
import random
import string
from Cryptodome.Cipher import Salsa20
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from base64 import b64encode


longest_line = 100 # also key length


def parse(arr):
    return ' '.join(str(x) for x in arr)


def to_ascii(strin):
    to_asc = []
    for i in strin:
        to_asc.append(ord(i))
    return to_asc


def to_bin(arr):
    to_binary = []
    for i, c in enumerate(arr):
        to_binary.append((bin(c)[2:]).zfill(8))
    return to_binary


def open_file(file_name):
    file = open(file_name, 'r')
    string_arr = file.read().splitlines()
    # print(string_arr)
    file.close()
    trunc = []
    for elem in string_arr:
        trunc_string = (elem[:longest_line]) if len(elem) > longest_line else elem
        trunc.append(trunc_string)
    # print(trunc)
    return trunc


# Generating standard key
def generate_key():
    return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase
                                 + string.digits) for _ in range(longest_line))


def salsa20_encrypt(line_msg, secret):
    cipher = Salsa20.new(key=secret)
    msg_cipher = cipher.nonce + cipher.encrypt(bytes(line_msg, 'ascii'))
    return str(msg_cipher)


def aes_encrypt(line_msg, secret):
    cipher = AES.new(secret, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(bytes(line_msg, 'ascii'))
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return str(ct)


def xor(char1, char2):
    return chr(ord(char1) ^ ord(char2))


def str_xor(string1, string2):
    if len(string1) > len(string2):
        return "".join([chr(ord(x) ^ ord(y)) for x, y in zip(string1[:len(string2)], string2)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for x, y in zip(string1, string2[:len(string1)])])


def parse_to_bin(arr):
    asc = []
    binary = []
    for i, strg in enumerate(arr):
        asc.append(to_ascii(strg))
    for i in asc:
        binary.append(to_bin(i))
    parsed = []
    for i in binary:
        parsed.append(parse(i))
    return parsed


if __name__ == '__main__':
    lines_arr = open_file("ogrod.txt")
    key = generate_key()
    xor_arr = []
    for line in lines_arr:
        xor_arr.append(str_xor(key, line))
    bin_xor = parse_to_bin(xor_arr)
    # save to file
    file_save = open("encrypted_pl.txt", 'w')
    for element in bin_xor:
        file_save.write(element + "\n")
    file_save.close()

    # Salsa20
    key_salsa = b'*Thirty-two byte (256 bits) key*'
    salsa_arr = []
    for line in lines_arr:
        salsa_arr.append(salsa20_encrypt(line, key_salsa))
    salsa_arr = parse_to_bin(salsa_arr)
    # save to file
    file_salsa = open("encrypted_salsa.txt", 'w')
    for element in salsa_arr:
        file_salsa.write(element + "\n")
    file_salsa.close()

    # AES in CTR mode
    key_aes = get_random_bytes(16)
    aes_arr = []
    for line in lines_arr:
        aes_arr.append(aes_encrypt(line, key_aes))
    aes_arr = parse_to_bin(aes_arr)
    # save to file
    file_aes = open("encrypted_aes.txt", 'w')
    for element in aes_arr:
        file_aes.write(element + "\n")
    file_aes.close()
