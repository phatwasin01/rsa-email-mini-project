import smtplib
from email.mime.text import MIMEText
import keyGenerator
import ED_byteSeq
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
import os
from dotenv import load_dotenv

def decrypt_message(ciphertext, nonce,encryptedKey ,signature,public_key_sender,private_key_reciever):
    # Receiver's code for decryption and signature verification
    # Decrypt the encrypted signature using the private key
    decrypted_signature = ED_byteSeq.rsaDecryptBytes2Bytes(public_key_sender, signature)
    decrypted_key = ED_byteSeq.rsaDecryptBytes2Bytes(private_key_reciever, encryptedKey)
    cipher = AES.new(decrypted_key, AES.MODE_EAX,nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext,decrypted_signature)
    print("Your Message Is : ",decrypted.decode())


# Generate RSA key pair
public_key_file_sender = 'public_key.pem'
public_key_sender = keyGenerator.extract_key_from_pem(public_key_file_sender)

public_key_file_reciever = 'public_key_reciever.pem'
private_key_file_reciever = 'private_key_reciever.pem'
public_key_reciever = keyGenerator.extract_key_from_pem(public_key_file_reciever)
private_key_reciever = keyGenerator.extract_key_from_pem(private_key_file_reciever)

# Simulate receiving an email
components = {}
with open("message_components.txt", "r") as file:
    for line in file:
        key, value = line.strip().split(": ")
        components[key] = bytes.fromhex(value)

# Extract the components
ciphertext = components["Ciphertext"]
nonce = components["Nonce"]
tag = components["Tag"]
signature = components["Encrypted Signature"]
key_encrypted = components["Encrypted Key"]
# decrypt_message(ciphertext,nonce,key,signature,public_key_sender,private_key_reciever)
decrypt_message(ciphertext, nonce, key_encrypted, signature, public_key_sender, private_key_reciever)
