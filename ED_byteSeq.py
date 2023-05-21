from math import *
from ED_bitSeq import * 

# Purpose:encrypt a byte sequence. Note that one byte is a block of 8 bits.
# Note: bytes is a built-in bytes in Python that represent a sequence of bytes. 
# to specify a byte, two hexdecimal digits are often used. For example \x1f represents
# a byte 0001|1111 because the hexdecimal digit 1 represnts 0001 while digit f represents 1111

# test:
# bytes = b'\x1f\x0f'; type(bytes)
# bytes = b'ab'; type(bytes)



#def byteSeq2bitSeq(b):
# Purpose: Convert a byte sequence into a 'bit-sequence' string
# Tests: byteSeq2bitSeq(b'\x1f\x0f') returns '0001111100001111'
#        byteSeq2bitSeq(b'ab') returns '01100001011000'

# def byteSeq2bitSeq(b):
# #     print(b)
#     s = ''.join(f'{x:08b}' for x in b)
#     # print(s)
#     return removePadding(s)
def byteSeq2bitSeq(b):
    # Initialize an empty string to store the bit-sequence
    bitSeq = ''
    
    # Loop over each byte in the sequence
    for byte in b:
        # Convert the byte to a binary string with leading zeros
        byteStr = bin(byte)[2:].zfill(8)
        # Append the binary string to the bit-sequence
        bitSeq += byteStr
    
    return bitSeq


# def rsaEncryptByteSeq2BitSeq(key, plainBytes)
# Purpose: Encrypt a byte sequence.
# Test: rsaEncryptByteSeq2BitSeq((13,77),b'ab')
def rsaEncryptByteSeq2BitSeq(key, plainBytes):
       bitSeq = byteSeq2bitSeq(plainBytes)
    #    print(bitSeq)
       return rsaEncrypt(key,bitSeq)


# def rsaEncryptString2BitSeq(key, plainString):
# Purpose: encrypt a string
# Test: rsaEncryptString2BitSeq((13,77),'ab')

def rsaEncryptString2BitSeq(key, plainString):
       byteSeq = bytearray(plainString,"ascii")
       return rsaEncryptByteSeq2BitSeq(key, byteSeq)
       




# Encrypt a string, return a byte sequence rather than a bit sequence?



# def bitSeqToBytes(bitSeq)
# Purpose: convert a bit sequence string to bytes
# Test: bitSeqToBytes('0001111100001111') returns b'\x1f\x0f'
def bitSeqToBytes(bitSeq):
       l = len(bitSeq)
       byteSeq = b''
       i = 0
       while i< l:
              if i + 8 <= l:
                     block = bitSeq[i: i + 8]
                     i = i + 8
              else:
                     block = bitSeq[i:l]
                     i = l
                     # padding OneAndZeros
                     block = block + "1" + "0"*(8- len(block) - 1)
                     
              integer_val = int(block,2)
              byteSeq = byteSeq + integer_val.to_bytes(1, 'big')
              
       return byteSeq




# def rsaEncryptString2Bytes(key, plainString):
# Purpose: Encrypt a string, returns a byte sequence
# Test: rsaEncryptString2Bytes((13,77),'ab') returns b'hY\x94'
def rsaEncryptString2Bytes(key, plainString):
       cipherBitSeq = rsaEncryptString2BitSeq(key, plainString)
       return bitSeqToBytes(cipherBitSeq)


# def rsaDecryptBytes2String(key, cipherBytes):
# Purpose: Descrypt a byte sequence, return a string
# test: rsaDecryptBytes2String((37,77),b'hY\x94') returns 'ab'
def rsaDecryptBytes2String(key, cipherBytes):
       cipherbitSeq = byteSeq2bitSeq(cipherBytes)
       plainbitSeq = rsaDecrypt(key,cipherbitSeq)
       byteSeq = bitSeqToBytes(plainbitSeq)
       return byteSeq.decode('ascii')




# Now let's test
# email = "hello"
# cipheredByteSeq = rsaEncryptString2Bytes((13,77),email)
# print("Encrypt ", email, "=>", cipheredByteSeq)
# decryptedEmail = rsaDecryptBytes2String((37,77),cipheredByteSeq)
# print("Decrypt ", cipheredByteSeq, "=>", decryptedEmail)



## Encrypt byteSeq => byteSeq

def rsaEncryptBytes2Bytes(key, byteSeq):
       cipherBitSeq = rsaEncryptByteSeq2BitSeq(key, byteSeq)
    #    print("TEST",cipherBitSeq)
       return bitSeqToBytes(cipherBitSeq)

## Descrypt byteSeq => byteSeq

def rsaDecryptBytes2Bytes(key, cipherBytes):
       cipherbitSeq = byteSeq2bitSeq(cipherBytes)
       plainbitSeq = rsaDecrypt(key,cipherbitSeq)
       byteSeq = bitSeqToBytes(plainbitSeq)
       return byteSeq