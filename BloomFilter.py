# CS 370 HW 2
# Bloom Filters
# Nick Alvey Implementation

# Overall strategy - creating an empty numpy array to represent open bits and generating a hash as given by each
# prompt and dividing it by the size of that hash (to represent the size of the bloom filter)

import hashlib
import numpy as np
from random_word import RandomWords

# Create Database
database_new = []

counter_no_new = 0
counter_maybe_new = 0
counter_false_positive_new = 0
counter_false_negative_new = 0

# Gathering Passwords

# Allow for an input file
input_file = input("Enter File Name for Password File To Be Read: ")
with open(input_file, "r", encoding="ISO-8859-1") as passwords:
    pass_iter = passwords.read().splitlines()

# Generate 1,000 random words
# pass_iter = []
# for run in range(1000):
#     pass_iter.append(RandomWords().get_random_word())

# Create Size of Bloom Filter - shooting for a 1 in 10,000 chance of getting a false positive

# calculation used from calculator here: https://hur.st/bloomfilter/

size_of_bloom_filter = int((len(pass_iter) * np.log(1/10000)) / np.log(1 / np.power(2, np.log(2))))

hash_array_new = np.zeros(size_of_bloom_filter)

print("###############################################################################")

print("Running SHA256 then SHA512 Filter")

print("###############################################################################")

for item in pass_iter:

    # Convert to Hash SHA256

    created_hash_256 = hashlib.sha256()
    string_for_hash_256 = item
    created_hash_256.update(bytes(string_for_hash_256, 'utf-8'))

    output_256 = created_hash_256.hexdigest()

    # Convert to Hash SHA256 to Hash SHA512

    created_hash_new = hashlib.sha512()
    string_for_hash_new = output_256
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
        if string_for_hash_new in database_new:
            counter_false_negative_new += 1

print()
print("This algorithm was hashed first with sha256 then with sha512")
print("Total Unique Passwords: " + str(counter_no_new) + ", Might Be In Database: " + str(counter_maybe_new)
      + ", Total False Positives: " + str(counter_false_positive_new) + ", Total False Negatives: "
      + str(counter_false_negative_new) +
      ", False Positive Rate is: " + str(float(counter_false_positive_new / counter_maybe_new) * 100) +
      "%" + ", False Negative Rate is: " + str(float(counter_false_negative_new / counter_no_new) * 100) + "%")

