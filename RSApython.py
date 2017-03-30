#!/usr/bin/env python3

#Nathan Barton
#Python implementation of RSA with OAEP PADDING SCHEME
#4109 CRYPTO
#Student Number 100792105

import math
import hashlib
import sys
import random
import os
import time

#Euclids Algorithm for determining Greatest Common Divisor
def euclid(a,b):

	if b > a:
		return euclid(b, a)

	if a % b == 0:
		return b

	return euclid(b, a % b)

#Basic RSA encryption, if not used in conjuction with OAEPpad(message) then their is no padding 
def encryptNoPadding(m,e,N):
	return pow(m,e,N)

#Basic RSA decryption, no unpadding must use OAEPunpad to unpad cipher 
def decryptNoPadding(c,d,N):
	return pow(c,d,N)

#prime number generator
def gen_prime(N=10**8, bases=range(2,20000)):

    p = 1
    while any(pow(base, p-1, p) != 1 for base in bases):
        p = random.SystemRandom().randrange(N)
    return p

#finds multiplicative inverse or the secret key d, using the extend euclidean algorithm
def multinv(modulus, value):

    x, lastx = 0, 1
    a, b = modulus, value
    while b:
        a, q, b = b, a // b, a % b
        x, lastx = lastx - q * x, x
    result = (1 - lastx * modulus) // value
    return result + modulus if result < 0 else result

#Used in milleRabin
def extractTwos(m):

    assert m >= 0
    i = 0
    while m & (2 ** i) == 0:
        i += 1
    return i, m >> i

#millerRabin test for primes this was open source code 
def millerRabin(n, k):
    """
    Miller Rabin pseudo-prime test
    return True means likely a prime, (how sure about that, depending on k)
    return False means definitely a composite.
    Raise assertion error when n, k are not positive integers
    and n is not 1
    """
    assert n >= 1
    # ensure n is bigger than 1
    assert k > 0
    # ensure k is a positive integer so everything down here makes sense

    if n == 2:
        return True
    # make sure to return True if n == 2

    if n % 2 == 0:
        return False
    # immediately return False for all the even numbers bigger than 2

    extract2 = extractTwos(n - 1)
    s = extract2[0]
    d = extract2[1]
    assert 2 ** s * d == n - 1

    def tryComposite(a):
        """Inner function which will inspect whether a given witness
        will reveal the true identity of n. Will only be called within
        millerRabin"""
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return None
        else:
            for j in range(1, s):
                x = pow(x, 2, n)
                if x == 1:
                    return False
                elif x == n - 1:
                    return None
            return False

    for i in range(0, k):
        a = random.randint(2, n - 2)
        if tryComposite(a) == False:
            return False
    return True  # actually, we should return probably true.

#Finds a prime number in a range between a and b, k is value for the miller Rabin function for how many times you want to test
#Throws and error if it takes to long
def findAPrime(a, b, k):

    x = random.randint(a, b)
    for i in range(0, int(10 * math.log(x) + 3)):
        if millerRabin(x, k):
            return x
        else:
            x += 1
    raise ValueError

#checks to see if x an y are co Prime using euclidean algorithm
def coPrime(x,y):
	if euclid(x,y) == 1:
		return True
	else:
		return False

# generate the keys and modulus for the system
def keygen(a,b,k):

	p = findAPrime(a,b,k)

	while True:
		q = findAPrime(a,b,k)  #finds two primes that are not equal
		if q != p:
			break

	N = p*q
	phi = (p-1)*(q-1)

	while True:
		e = random.randint(1, phi) #finds public exponent e
		if coPrime(e, phi):
			break

	d = multinv(phi, e) #private exponent d

	return (N, e, d, p, q)

#converts a string to an array of its ascii values
def stringToAscii(m):
	strlist = [ord(c) for c in m]
	return strlist

#gets the length of an integer (python website)
def bit_length(self):
    s = bin(self)       # binary representation:  bin(-37) --> '-0b100101'
    s = s.lstrip('-0b') # remove leading zeros and minus sign
    return len(s)       # len('100101') --> 6

#BASIC padding, no k0 or k1 no hash functions
#simply follows through with the XOR's 
#generates x and y and concatenates them together
def OAEPpad(message):
	r = random.getrandbits(bit_length(message))
	x = r^message
	y = x^r
	return (x,y,((x << bit_length(message)) | y))

#BASIC Unpadding again no k0 or k1 and no hash functions
def OAEPunpad(cipher,x,y):
	r = y^x
	m = x^r
	return m	

def main():

	N=e=d=p=q=phi=x=y=cipher = 0 # initialize all values

	def infoMenu(): # simple GUI for info menu

		os.system('cls' if os.name == 'nt' else 'clear')
		print ("="*100)
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "*********  *********  *********" + " "*37 + "|")
		print ("|" + " "*30 + "**     **  **         **     **" + " "*37 + "|")
		print ("|" + " "*30 + "**    ***  *********  *********" + " "*37 + "|")
		print ("|" + " "*30 + "**  ***    *********  **     **" + " "*37 + "|")
		print ("|" + " "*30 + "**  **            **  **     **" + " "*37 + "|")
		print ("|" + " "*30 + "**   ****  *********  **     **" + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "      By: Nathan Barton        " + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "  1. Generate new key         " + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "  2. Display details           " + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "  0. Return to Main Menu       " + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("="*100)

		#takes user input to decide what to do next
		while True:
			choice = input ("What would you like to do? (Enter choice number): ")

			if choice == '1':

				nonlocal N,e,d,p,q,phi # NON LOCAL IS ONLY AVAILABLE IN PYTHON 3 IMPORTANT!!! 

				N,e,d,p,q = keygen(2**511,2**512,100) #generate new info with 512 bit primes

				phi = (p-1)*(q-1)
				
				print ("N: %d" % N)
				print ("")
				print ("e: %d" % e)
				print ("")
				print ("d: %d" % d)
				print ("")
				print ("p: %d" % p)
				print ("")
				print ("q: %d" % q)
				print ("")

				print ("New Keys Generated.")
				print ("")

			elif choice == '2':
				detailsMenu()
			elif choice == '0':
				mainMenu()
			else:
				print ("Sorry invalid choice.")

	def mainMenu(): # simple GUI for main menu
	
		os.system('cls' if os.name == 'nt' else 'clear')

		print (sys.version)
		print ("="*100)
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "*********  *********  *********" + " "*37 + "|")
		print ("|" + " "*30 + "**     **  **         **     **" + " "*37 + "|")
		print ("|" + " "*30 + "**    ***  *********  *********" + " "*37 + "|")
		print ("|" + " "*30 + "**  ***    *********  **     **" + " "*37 + "|")
		print ("|" + " "*30 + "**  **            **  **     **" + " "*37 + "|")
		print ("|" + " "*30 + "**   ****  *********  **     **" + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "      By: Nathan Barton        " + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "  1. Public Keys               " + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "  2. Your Info                 " + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "  3. Encrypt/Decrypt           " + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*30 + "  0. Exit                      " + " "*37 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("|" + " "*98 + "|")
		print ("="*100)

		#takes user input to decide what to do next
		while True:
			choice = input ("What would you like to do? (Enter choice number): ")

			if choice == '1':
				print ("Sorry Not Done this Yet") 
			elif choice == '2':
				infoMenu()
			elif choice == '3':
				if N == 0:
					print ("Sorry keys have not been generated yet")
				else:
					encryptMenu()
			elif choice == '0':
				print ("Goodbye and Have a Nice Day")
				time.sleep(1)
				exit()
			else:
				print ("Sorry invalid choice.")

	def detailsMenu(): #details menu shows you the current information

		os.system('cls' if os.name == 'nt' else 'clear')
		print ("="*100)
		print ("")
		print ("Current Info")
		print ("")
		print ("N = %d" % N)
		print ("")
		print ("e = %d" % e)
		print ("")
		print ("d = %d" % d)
		print ("")
		print ("p = %d" % p)
		print ("")
		print ("q = %d" % q)
		print ("")
		print ("phi = %d" % phi)
		print ("")
		print ("")
		print ("")
		print ("="*100)

		while True:
			choice = input ("Enter 0 to return to the info menu: ")

			if choice == '0':
				infoMenu()
			else:
				print ("Sorry invalid choice.")


	def encryptMenu(): #encryption menu for encrypt or decrypt 

		nonlocal cipher,x,y # NON LOCAL IS ONLY AVAILABLE IN PYTHON 3 IMPORTANT!!! 

		os.system('cls' if os.name == 'nt' else 'clear')		
		print ("="*100)
		print ("")
		print ("1. Encrypt ")
		print ("")
		print ("2. Decrypt ")
		print ("")
		print ("0. Return to Main Menu")
		print ("")
		print ("="*100)

		while True:
			choice = input("Encrypt or Decrypt? ")

			if choice == '1':

				message = input ("Enter Message: ") #Get message
				message = stringToAscii(message) #convert to list of int values

				print ("")
				print ("Message in Ascii: ")
				print (message)
				print ("")

				hexString = '0x'

				for c in message:
					hexString = hexString + hex(c)[2:] #create a hex string based of list of ints

				print ("Message Hex form: %s"  % hexString)
				print ("")

				cipher = int(hexString,16) #convert hex to integer

				print ("Non padded: %d" % cipher)
				print ("")

				x,y,cipher = OAEPpad(cipher) #pad the message

				print ("Padded message: %d" % cipher)
				print ("")

				cipher = encryptNoPadding(cipher,e,N) # encrypt the padded message

				print ("Encrypted Message = %d" % cipher)
				print ("")

			elif choice == '2':

				if cipher == 0:
					print ("Sorry no cipher detected.")
				else:
					print ("")

					decryptedMessage = decryptNoPadding(cipher,d,N) #decrypt message

					print ("Decrypt Message: %d" % decryptedMessage)
					print ("")

					decryptedMessage = OAEPunpad(decryptedMessage,x,y) #unpad message

					print ("Unpad Message: %d" % decryptedMessage)
					print ("")

					decryptedMessage = hex(decryptedMessage).rstrip("L").lstrip("0x") #convert to hex

					print ("Message to Hex: %s" % decryptedMessage)
					print ("")

					decryptedMessage = bytes.fromhex(decryptedMessage).decode('ascii') #convert to string

					print ("Final decryption: %s" % decryptedMessage)
					print ("")

			elif choice =='0':

				mainMenu()

			else:
				print ("Sorry wrong Input.")



	mainMenu() #start the main menu

#START THE PROGRAM
main()

