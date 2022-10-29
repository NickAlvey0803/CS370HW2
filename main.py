# CS 370 HW 2
# Bloom Filters
# Nick Alvey Implementation

# Comparison Document

import hashlib
import numpy as np
from random_word import RandomWords

# Create Database for Passwords (un-encrypted)

database_256 = []
database_512 = []
database_md5 = []
database_new = []

counter_no_256 = 0
counter_maybe_256 = 0
counter_false_positive_256 = 0
counter_no_512 = 0
counter_maybe_512 = 0
counter_false_positive_512 = 0
counter_no_md5 = 0
counter_maybe_md5 = 0
counter_false_positive_md5 = 0
counter_no_new = 0
counter_maybe_new = 0
counter_false_positive_new = 0

# Gathering Passwords

# Allow for an input file
# pass_iter = []
input_file = input("Enter File Name for Password File To Be Read: ")
with open(input_file, "r") as passwords:
    # for line in passwords:
    #     for word in line.split():
    #         pass_iter.append(word)
    pass_iter = passwords.read().splitlines()

# Generate 1,000 random words
# pass_iter = []
# for run in range(1000):
#     pass_iter.append(RandomWords().get_random_word())

# Create Size of Bloom Filter - shooting for a 1 in 100,000 chance of getting a false positive

# calculation used from calculator here: https://hur.st/bloomfilter/

size_of_bloom_filter = int((len(pass_iter) * np.log(1/100000)) / np.log(1 / np.power(2, np.log(2))))
# print(size_of_bloom_filter)

hash_array_256 = np.zeros(size_of_bloom_filter)
hash_array_512 = np.zeros(size_of_bloom_filter)
hash_array_md5 = np.zeros(size_of_bloom_filter)
hash_array_new = np.zeros(size_of_bloom_filter)

# Perform with SHA256

print("###############################################################################")

print("Taking Input and Testing with SHA256 Bloom Filter")

print("###############################################################################")

for item in pass_iter:

    # Convert to Hash SHA256

    created_hash_256 = hashlib.sha256()
    string_for_hash_256 = str(item)
    created_hash_256.update(bytes(string_for_hash_256, 'utf-8'))

    output_256 = created_hash_256.hexdigest()

    location_of_pass_256 = int(output_256, base=16) % size_of_bloom_filter

    # Check if password in library SHA256

    if hash_array_256[location_of_pass_256] == 1:

        # Check Database
        print("Pass: " + item + ", Result: " + "maybe")
        counter_maybe_256 += 1

        if string_for_hash_256 in database_256:
            pass
        else:
            database_256.append(string_for_hash_256)
            counter_false_positive_256 += 1


    else:
        hash_array_256[location_of_pass_256] = 1
        print("Pass: " + item + ", Result: " + "no")
        counter_no_256 += 1
        database_256.append(string_for_hash_256)

print()
print("Total Unique Passwords: " + str(counter_no_256) + ", Might Be In Database: " + str(counter_maybe_256)
      + ", Total False Positives: " + str(counter_false_positive_256))
print()

# Perform with SHA512

print("###############################################################################")

print("Taking Input and Testing with SHA512 Bloom Filter")

print("###############################################################################")

for item in pass_iter:

    # Convert to Hash SHA512

    created_hash_512 = hashlib.sha512()
    string_for_hash_512 = item
    created_hash_512.update(bytes(string_for_hash_512, 'utf-8'))

    output_512 = created_hash_512.hexdigest()

    location_of_pass_512 = int(output_512, base=16) % size_of_bloom_filter


    # Check if password in library SHA512

    if hash_array_512[location_of_pass_512] == 1:

        # Check Database
        print("Pass: " + item + ", Result: " + "maybe")
        counter_maybe_512 += 1

        if string_for_hash_512 in database_512:
            pass
        else:
            database_512.append(string_for_hash_512)
            counter_false_positive_512 += 1


    else:
        hash_array_512[location_of_pass_512] = 1
        print("Pass: " + item + ", Result: " + "no")
        database_512.append(string_for_hash_512)
        counter_no_512 += 1

print()
print("Total Unique Passwords: " + str(counter_no_512) + ", Might Be In Database: " + str(counter_maybe_512)
      + ", Total False Positives: " + str(counter_false_positive_512))
print()

# Perform with md5

print("###############################################################################")

print("Taking Input and Testing with md5 Bloom Filter")

print("###############################################################################")

for item in pass_iter:

    # Convert to Hash md5

    created_hash_md5 = hashlib.md5()
    string_for_hash_md5 = item
    created_hash_md5.update(bytes(string_for_hash_md5, 'utf-8'))

    output_md5 = created_hash_md5.hexdigest()


    location_of_pass_md5 = int(output_md5, base=16) % size_of_bloom_filter

    # Check if password in library md5

    if hash_array_md5[location_of_pass_md5] == 1:

        # Check Database
        print("Pass: " + item + ", Result: " + "maybe")
        counter_maybe_md5 += 1

        if string_for_hash_md5 in database_md5:
            pass
        else:
            database_md5.append(string_for_hash_md5)
            counter_false_positive_md5 += 1


    else:
        hash_array_md5[location_of_pass_md5] = 1
        print("Pass: " + item + ", Result: " + "no")
        database_md5.append(string_for_hash_md5)
        counter_no_md5 += 1

print("###############################################################################")

print("Running SHA256 then SHA512 Filter")

print("###############################################################################")

for item in pass_iter:

    # Convert to Hash md5

    created_hash_md5 = hashlib.sha256()
    string_for_hash_md5 = item
    created_hash_md5.update(bytes(string_for_hash_md5, 'utf-8'))

    output_md5 = created_hash_md5.hexdigest()

    created_hash_new = hashlib.sha512()
    string_for_hash_new = output_md5
    created_hash_new.update(bytes(string_for_hash_new, 'utf-8'))

    output_new = created_hash_new.hexdigest()

    location_of_pass_new = int(output_new, base=16) % size_of_bloom_filter

    # Check if password in library md5

    if hash_array_new[location_of_pass_new] == 1:

        # Check Database
        print("Pass: " + item + ", Result: " + "maybe")
        counter_maybe_new += 1

        if string_for_hash_new in database_new:
            pass
        else:
            database_new.append(string_for_hash_new)
            counter_false_positive_new += 1


    else:
        hash_array_new[location_of_pass_new] = 1
        print("Pass: " + item + ", Result: " + "no")
        database_new.append(string_for_hash_new)
        counter_no_new += 1

print()
print("Total Unique Passwords: " + str(counter_no_new) + ", Might Be In Database: " + str(counter_maybe_new)
      + ", Total False Positives: " + str(counter_false_positive_new))
print()

print("###############################################################################")
print("RECAP")
print("###############################################################################")

print("SHA256")
print("Total Unique Passwords: " + str(counter_no_256) + ", Might Be In Database: " + str(counter_maybe_256)
      + ", Total False Positives: " + str(counter_false_positive_256) +
      ", False Positive Rate is: " + str(float(counter_false_positive_256 / counter_maybe_256) * 100) + "%")

print("###############################################################################")

print("SHA512")
print("Total Unique Passwords: " + str(counter_no_512) + ", Might Be In Database: " + str(counter_maybe_512)
      + ", Total False Positives: " + str(counter_false_positive_512) +
      ", False Positive Rate is: " + str(float(counter_false_positive_512 / counter_maybe_512) * 100) + "%")

print("###############################################################################")

print("md5")
print("Total Unique Passwords: " + str(counter_no_md5) + ", Might Be In Database: " + str(counter_maybe_md5)
      + ", Total False Positives: " + str(counter_false_positive_md5) +
      ", False Positive Rate is: " + str(float(counter_false_positive_md5 / counter_maybe_md5) * 100) + "%")

print("###############################################################################")

print("first sha256 then sha512")
print("Total Unique Passwords: " + str(counter_no_new) + ", Might Be In Database: " + str(counter_maybe_new)
      + ", Total False Positives: " + str(counter_false_positive_new) +
      ", False Positive Rate is: " + str(float(counter_false_positive_new / counter_maybe_new) * 100) + "%")