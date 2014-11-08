1. UTEID: nbs439; yj3343;

FIRSTNAME: Nishil; Yinjie;

LASTNAME: Shah; Ji;

CSACCOUNT: nishil; jiyinjie;

EMAIL: nishil94@utexas.edu; jiyinjie@utexas.edu;

2. The program is divided up into two main components. 

The first part is encryption. During this phase, different steps of operation will be performed on the plaintext in order and combined with a unique 128-bit key.
There are several steps to the encryption phase, and there will be 10 rounds of these encryption steps.
In the first round, the algorithm will take the plaintext and perform the addRoundKey process with the ciphertext, which is essentially an xor function run across
all 128 bit of the plaintext.
In the second to ninth round, we will perform the subBytes(), shiftRows(), mixColumns(), addRoundKey() in sequential order to obfuscate the plaintext.
subBytes() substitutes the current state of the encryption with values from a pre-determined s-box.
shiftRows() rotates the rows of the encryption matrix to the left - 0 times for 1st row, 1 time for 2nd row, 2 times for 3rd row, 3 times for last row
mixColumns() performs modulo multiplication in the Galois Field.
The subBytes() and addRoundKey() provides confusion, where as shiftRows() and mixCoumns() provide diffusion.
In the last and 10th round, we will only perform subBytes(), shiftRows(), and addRoundKey(), skipping the mixColumn step.
As a result, the AES encryption produces a very robust encryption of the plaintext. If an attacker does not have the original cipherkey, he/she would not have 
the ability to brute force this encryption in his/her lifetime.

The second part of the project is decrpytion. Once you understand the encryption part of AES, the decryption is relatively straightforward. You start by taking the
original key and expanding it to its last iteration. perform the addRound on the encrypted file to undo round 10 of encryption. Then you simply reverse all the 
steps used to create encryption. Note: we wrote inverse functions to undo everything. The invMixColumns function was referenced in the comments, as we did not have
enough time to write our own version/forgot to ask Dr. Young for his version.

3. The addRoundKey() doesn't work properly during decryption phase, but everything else should work. Reason for the bug is largely due
to time constraint with other exams (namely, 439) and project, one
of the team member also had to drive back to Houston on 11/07/2014

4. total test case created: 2

	input: aaaa1111bbbb2222cccc3333dddd4444
	key: 1a2b3c4d5e6faffd1001a1f14c123abc
	encrypted cipher: d67cb4bdfa99e86c698041cadf5a9e8

	input: abcd123455bb66cc77ee88dd
	key: abba1345effe6012cdcd9912a1b2c3e4
	encrypted cipher: 84392a33043878fc27f977bfd1a93d



	
