# Program for decoding stream cipher cryptograms encoded with the same key
# Algorithm based on https://crypto.stackexchange.com/questions/91988/using-whitespace-to-break-many-time-pad-stream-cipher
import math


# Make an array of cryptograms from a file
def get_cipher(file_name):
    # Open a file with the ciphered messages
    file = open(file_name, 'r')
    cipher = file.read().splitlines()
    file.close()
    # print(cipher)
    sep_cipher = []
    for k, c in enumerate(cipher):
        sep_cipher.append(parse_cipher(c))
    return sep_cipher


# Parse cryptograms each character into new index
def parse_cipher(line) -> str:
    chars = []
    temp = str(line).split(' ')
    for c in temp:
        chars.append(chr(int(c, 2)))
    return "".join(chars)


# Search for the longest string
def get_longest(arr):
    return max(enumerate(arr), key=lambda x: len(x[1]))[0]


# Dictionary with letters and frequency (ASCII characters)
letters_freq = {
    'a': 99, 'b': 15, 'c': 44, 'd': 33, 'e': 88, 'f': 3, 'g': 15, 'h': 11,
    'i': 83, 'j': 23, 'k': 36, 'l': 40, 'm': 29, 'n': 58, 'o': 86, 'p': 32,
    'q': 2, 'r': 47, 's': 50, 't': 40, 'u': 25, 'v': 1, 'w': 47, 'x': 1,
    'y': 38, 'z': 66, ' ': 100, ',': 7, '.': 15, '-': 3, '"': 3, '!': 10,
    '?': 10, ':': 3, ';': 3, '(': 10, ')': 10
}

# Numbers frequency
for i in range(48, 58):
    letters_freq[chr(i)] = 20

# Capital letters frequency
for i in range(65, 91):
    letters_freq[chr(i)] = math.ceil(letters_freq[chr(i + 32)] * 0.53)


def xor(char1, char2):
    return chr(ord(char1) ^ ord(char2))


def str_xor(string1, string2):
    if len(string1) > len(string2):
        return "".join([chr(ord(x) ^ ord(y)) for x, y in zip(string1[:len(string2)], string2)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for x, y in zip(string1, string2[:len(string1)])])


def stream_xor(arr):
    index = get_longest(arr)
    # array for cryptograms xorred with the chosen index one
    arr_xor = []
    length = 0
    for q, c in enumerate(arr):
        # xor index stream with every other one
        # c_1 = p_1 XOR k and c_y = p_y XOR k
        # c_1 XOR c_y = p_1 XOR k XOR p_y XOR k = p_1 XOR p_y
        if q == index:
            # Don't XOR with yourself
            continue
        arr_xor.append(str_xor(c, arr[index]))
        length += 1
    # print(arr_xor)
    return guess(arr_xor, arr[index])


def guess(arr, longest):
    # Our goal is to guess p_1' (decrypted position) and then
    # p_1' XOR p_1 XOR p_y = p_y'
    # Now, if p_y' is an invalid character, we know that the guessed p_1' is wrong
    key_guess = []
    # print(longest)
    for p, c_from_longest in enumerate(longest):
        # print("------------POSITION:", p)
        # Guess each character from position of the longest cryptogram
        # Array to store possible guesses for p_1' based on validity of p_y'
        possible_p_1_prime = []
        for alpha in letters_freq:
            counter = 0
            cnt_length = 0
            # print("ALPHA:", alpha)
            for j, cipher in enumerate(arr):
                # Cryptogram needs to have an i-position
                # print("CIPEHR: ", cipher)
                if len(cipher) > p:
                    cnt_length += 1
                    p_y_prime = xor(alpha, cipher[p])
                    # print("PY'", p_y_prime)
                    # Check if p_y' is a valid character
                    if p_y_prime in letters_freq:
                        counter += 1
                    else:
                        break
                    # print("COUNTER ", counter)
            if counter == cnt_length and cnt_length != 0:
                possible_p_1_prime.append(alpha)
            # print(possible_p_1_prime)
        # perform frequency analysis on p_y' with each possible p_1'
        if len(possible_p_1_prime) > 0:
            best_p_1_prime = possible_p_1_prime[0]
            best_freq = 0
            for h, p_1_prime in enumerate(possible_p_1_prime):
                freq = 0
                for j, cipher in enumerate(arr):
                    if len(cipher) > p:
                        p_y_prime = xor(p_1_prime, cipher[p])
                        freq += letters_freq[p_y_prime]
                    if freq >= best_freq:
                        best_freq = freq
                        best_p_1_prime = p_1_prime
            # key is c_ 1 XOR p_1' = p_1
            key_guess.append(xor(best_p_1_prime, c_from_longest))
    return key_guess


if __name__ == '__main__':
    parsed = get_cipher("cipher.txt")
    key_arr = stream_xor(parsed)
    key = "".join(key_arr)
    # print(key)
    deciphered = []
    for r, char in enumerate(parsed):
        deciphered.append(str_xor(key, char))

    print(deciphered)
    print("------------------------------")
    for i, message in enumerate(deciphered):
        print(message)
