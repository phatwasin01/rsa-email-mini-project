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

def send_email(sender_email, receiver_email, password, subject, message):
    # Create the MIME message
    mime_message = MIMEText(message)
    mime_message["From"] = sender_email
    mime_message["To"] = receiver_email
    mime_message["Subject"] = subject

    # Create an SMTP session
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        # Start TLS for security
        server.starttls()

        # Login to the sender's email account
        server.login(sender_email, password)

        # Send the email
        server.send_message(mime_message)

        print("Email sent successfully!")

load_dotenv()
# Usage example
sender_email = "6322772409@g.siit.tu.ac.th"
# receiver_email = "phatwasin01@gmail.com"
receiver_email = "6322775122@g.siit.tu.ac.th"
password = os.getenv("PASSWORD")
subject = "Hello"
message = """A purely peer-to-peer version of electronic cash would allow online
payments to be sent directly from one party to another without going through a
financial institution. Digital signatures provide part of the solution, but the main
benefits are lost if a trusted third party is still required to prevent double-spending.
We propose a solution to the double-spending problem using a peer-to-peer network.
The network timestamps transactions by hashing them into an ongoing chain of
hash-based proof-of-work, forming a record that cannot be changed without redoing
the proof-of-work. The longest chain not only serves as proof of the sequence of
events witnessed, but proof that it came from the largest pool of CPU power. As
long as a majority of CPU power is controlled by nodes that are not cooperating to
attack the network, they'll generate the longest chain and outpace attackers. The
network itself requires minimal structure. Messages are broadcast on a best effort
basis, and nodes can leave and rejoin the network at will, accepting the longest
proof-of-work chain as proof of what happened while they were gone."""

# Generate RSA key pair
public_key_file = 'public_key.pem'
private_key_file = 'private_key.pem'
public_key = keyGenerator.extract_key_from_pem(public_key_file)
private_key = keyGenerator.extract_key_from_pem(private_key_file)

public_key_file_reciever = 'public_key_reciever.pem'
private_key_file_reciever = 'private_key_reciever.pem'
public_key_reciever = keyGenerator.extract_key_from_pem(public_key_file_reciever)
private_key_reciever = keyGenerator.extract_key_from_pem(private_key_file_reciever)
# Encrypt the message using AES
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(message.encode())
nonce = cipher.nonce

# Sign the digest of the ciphertext using the private key
signature = ED_byteSeq.rsaEncryptBytes2Bytes(private_key, tag)
key_encrypted = ED_byteSeq.rsaEncryptBytes2Bytes(public_key_reciever, key)

# Send the ciphertext, nonce, tag, and encrypted signature to the receiver


with open("message_components.txt", "w") as file:
    file.write("Ciphertext: " + ciphertext.hex() + "\n")
    file.write("Nonce: " + nonce.hex() + "\n")
    file.write("Tag: " + tag.hex() + "\n")
    file.write("Encrypted Signature: " + signature.hex() + "\n")
    file.write("Encrypted Key: " + key_encrypted.hex() + "\n")
with open("message_components.txt", "r") as file:
    encrpyted_message = file.read()
    send_email(sender_email, receiver_email, password, subject, encrpyted_message)
