To run this program (BloomFilter.py), you will need to do the following:

- In the folder with main.py, you will need to install the requirements as listed in requirements.txt. This can be done manually or by typing in:

"Pip install -r requirements.txt"


The program can be run 2 ways: either by entering some file that contains words to be checked, or you can generate 1,000 random words. You need to go into the program to and uncomment under the section: 

"# Generate 1000 Random Words"

And comment out the section "Allow for an Input File". The file dictionary.txt has been added to the folder from the Canvas page.

At the end of the run, it will "Recap" the results of the runs in case the user does not want to scroll through the printout. This includes how many unique passwords were found (true negatives), how many it said might be in the database, how many were false positives of being in the database, and how many it said were unique (negative) but were actually in the database (false negatives).

Note:

I wrote a program in main.py that compares SHA256, SHA512, md5, and combining SHA256 and 512 hashing algorithms to make a bloom filter. Run that at your own risk (it works but will take 4x the BloomFilter.py program).

It runs an SHA256 hash algorithm, SHA512 algorithm, and md5 algorithm and displays the results for a bloom filter of variable size based on the input.
It will output each input and the result of the bloom filter saying whether it is not in the database, or it might be in the database. At the end of each run of an algorithm, it will tally how many unique passwords were found, how many it said might be in the database, and how many were false positives of being in the database. At the end of all the runs, it will recap the results.