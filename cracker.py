# import binascii
# import hashlib
import crypt
# import os
# import string
# from secrets import choice as randchoice
# from multiprocessing import Process, Queue
# from multiprocessing import Pool, freeze_support
# from threading import Thread
import time
from pathlib import Path

wordlist_default = "rockyou_utf8.txt"
shadow_default = "shadow"


def start_password_cracker():
    print("Starting password cracker.")
    global wordlist_default
    global shadow_default
    # wordlist_default = "test.txt"
    # shadow_default = "shadow"

    valid_shadow = False
    while not valid_shadow:
        print("Enter shadow path:")
        shadow_path = input()
        my_file = Path(shadow_path)
        if my_file.is_file():
            shadow_default = shadow_path
            valid_shadow = True
        else:
            print(f"File does not exist, try again.")

    valid_wordlist = False
    while not valid_wordlist:
        print("Enter wordlist path:")
        wordlist_path = input()
        my_file = Path(wordlist_path)
        if my_file.is_file():
            wordlist_default = wordlist_path
            valid_wordlist = True
        else:
            print(f"File does not exist, try again.")

    crack_list = read_shadow()
    
    for my_password in crack_list:
        time_start = time.perf_counter()
        username = my_password[0]
        algo = my_password[1]
        my_salt = my_password[2]
        my_hash = my_password[3]
        password_found, password = dictionary_attack(algo, my_salt, my_hash)

        process_time = time.perf_counter() - time_start
        if password_found:
            print(f"{username}: {password} - (PASSWORD FOUND!) Time: {process_time}")
        else:
            print(f"{username} - (Password not found.)")


def read_shadow():
    crack_list = []
    with open(file=shadow_default, mode='r', encoding='utf-8') as file:
        fp = [line.rstrip('\n') for line in file]
        for entry in fp:
            line = entry.strip()
            if line.isspace() or line.startswith('#'):
                continue
            l_split = line.split(":")
            username = l_split[0]
            password_hash = l_split[1]

            if not password_hash.startswith("$"):
                continue

            p_split = password_hash.split("$")

            hash_type = p_split[1]
            salt = p_split[2]
            my_hash = p_split[3]
            if hash_type == "y":
                # my_input = password_hash.rsplit("$", 1)[1]
                hash_type = f"{p_split[1]}${p_split[2]}"
                salt = p_split[3]
                # salt = my_input
                my_hash = p_split[4]
            # print(f"Hash_type = {hash_type}")
            # print(f"Salt = {salt}")
            # print(f"Hash = {my_hash}")

            crack_list.append((username, hash_type, salt, my_hash))

    return crack_list


def dictionary_attack(algo, my_salt, my_hash):
    global wordlist_default
    wordlist_path = wordlist_default
    password_found = False
    password = ""
    # salt = f"${algo}${my_salt}"
    salt = f"${algo}${my_salt}"
    # if algo == "1":
    #     print("\tMD5")
    #     salt = f"$1${my_salt}"
    # if algo == "2a":
    #     print("\tBlowfish")
    #     salt = f"$2a${my_salt}"
    # if algo == "5":
    #     print("\tSHA-256")
    #     salt = f"$5${my_salt}"
    # if algo == "6":
    #     print("\tSHA-512")
    #     salt = f"$6${my_salt}"

    with open(file=wordlist_path, mode='r', encoding='utf-8') as file:
        # wordlist = [line.rstrip('\n') for line in file]
        # wordlist = file
        for word_s in file:
            word = word_s.rstrip('\n').strip()

            if word.isspace():
                continue
            # print("password")
            # print(word)
            # print("6IzyZ7qpZo7oo8in")
            # print(salt)
            # c_output = sha512_crypt(word, salt=salt, rounds=5000)
            c_output = crypt.crypt(word, salt)
            # print(c_output)
            p_split = c_output.split("$")
            if algo.startswith("y"):
                new_hash = p_split[4]
            else:
                new_hash = p_split[3]
            # print(f"Hash = {my_hash}")

            if new_hash == my_hash:
                password_found = True
                password = word
                break

    return password_found, password


# def sha512_crypt(password, salt=None, rounds=None):
#     if salt is None:
#         salt = ''.join([randchoice(string.ascii_letters + string.digits)
#                         for _ in range(8)])
#
#     prefix = '$6$'
#     if rounds is not None:
#         rounds = max(1000, min(999999999, rounds or 5000))
#         prefix += 'rounds={0}$'.format(rounds)
#     return crypt.crypt(password, prefix + salt)



if __name__ == '__main__':
    start_password_cracker()

# try:  # 3.6 or above
#     from secrets import choice as randchoice
# except ImportError:
#     from random import SystemRandom
#     randchoice = SystemRandom().choice


# m = hashlib.sha512()
# m.update((salt + word).encode("utf-8"))
# m_output = m.hexdigest()
# print(f"m={m_output}")
# print(f"g={hex(int(my_hash, 16))}")
# if m_output == my_hash:
#     password_found = True
#     password = word
#     print("FRONT SALT!")
#     break

# n = hashlib.sha512()
# n.update((word + salt).encode("utf-8"))
# n_output = n.digest().decode("utf-8")
# print(f"n={n_output}")
# if n_output == my_hash:
#     password_found = True
#     password = word
#     print("BACK SALT!")
#     break

