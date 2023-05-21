from math import *
import random
import primeGenerator as primeGenerator
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
def mulInverse(a, m) : 
	m0 = m 
	y = 0
	x = 1
	if (m == 1) : 
		return 0
	while (a > 1) : 
		# q is quotient 
		q = a // m 
		t = m 
		# m is remainder now, process 
		# same as Euclid's algo 
		m = a % m 
		a = t 
		t = y 
		# Update x and y 
		y = x - q * y 
		x = t 
	# Make x positive 
	if (x < 0) : 
		x = x + m0 
	return x 
def generateKeysSender():
        p = int(primeGenerator.generatePrime());
        q = int(primeGenerator.generatePrime());
        n = p*q
        e = 65537 #65537  # Public exponent Prime Number
        phiOfn = (p-1)*(q-1)

        if(gcd(e,phiOfn)!=1):
            return False
        d = mulInverse(e,phiOfn)
       # Save public key
        public_key = (e,n)
        private_key = (d,n)
        public_key_str = f"e={public_key[0]}\nn={public_key[1]}"
        save_key_to_pem(public_key_str, "RSA PUBLIC", "public_key.pem")
        # Save private key
        private_key_str = f"d={private_key[0]}\nn={private_key[1]}"
        save_key_to_pem(private_key_str, "RSA PRIVATE", "private_key.pem")
        print("The key pair is generated and saved in public_key.pem and private_key.pem")
def generateKeysReciever():
        p = int(primeGenerator.generatePrime());
        q = int(primeGenerator.generatePrime());
        n = p*q
        e = 65537 #65537  # Public exponent Prime Number
        phiOfn = (p-1)*(q-1)
        if(gcd(e,phiOfn)!=1):
            return False
        d = mulInverse(e,phiOfn)
       # Save public key
        public_key = (e,n)
        private_key = (d,n)
        public_key_str = f"e={public_key[0]}\nn={public_key[1]}"
        save_key_to_pem(public_key_str, "RSA PUBLIC", "public_key_reciever.pem")
        # Save private key
        private_key_str = f"d={private_key[0]}\nn={private_key[1]}"
        save_key_to_pem(private_key_str, "RSA PRIVATE", "private_key_reciever.pem")
        print("The key pair is generated and saved in public_key.pem and private_key.pem")

def save_key_to_pem(key, key_type, file_name):
    # Format the key as a string
    key_str = f"-----BEGIN {key_type} KEY-----\n{base64.b64encode(key.encode()).decode()}\n-----END {key_type} KEY-----\n"

    # Save the key to a PEM file
    with open(file_name, "w") as f:
        f.write(key_str)

# import base64

def extract_key_from_pem(file_name):
    with open(file_name, 'r') as f:
        pem_data = f.read()

    # Extract key data from PEM format
    key_data = pem_data.split('-----')[2]

    # Decode and parse the key data
    decoded_key_data = base64.b64decode(key_data)
    key_str = decoded_key_data.decode('utf-8')

    # Extract values of e and n from the key string
    key_parts = key_str.split('\n')
    e = int(key_parts[0].split('=')[1])
    n = int(key_parts[1].split('=')[1])

    return e, n

