from math import *
import modularExp
# def bitSeq2PlainBlocks(bitSeq,plainBlockSize)
# Singature: (string, integer) => list of strings
# Purpose: break down a bit sequence into plain blocks, padding OneAndZeroes
# Example: bitSeq2PlainBlocks("1011000110101011", 7) => ['1011000', '1101010', '1110000']
# Note that the last block "11" originally contains only two bits, but we need to
# pad "10000" to make it a 7-bit block.

def bitSeq2PlainBlocks(bitSeq,plainBlockSize):
       # padding OneAndZeroes 10...00, where the number 0 is plainBlockSize - len(bitSeq)%plainBlockSize
       bitSeq = bitSeq + "1" # always padding 1
       if len(bitSeq)%plainBlockSize != 0:
              bitSeq = bitSeq + "0" * (plainBlockSize - len(bitSeq)%plainBlockSize)
       plainBlocks = []
       noOfblocks = int(len(bitSeq)/plainBlockSize)
       for i in range(0,noOfblocks):
             plainBlocks.append(bitSeq[i*plainBlockSize:(i+1)*plainBlockSize])
       return plainBlocks





# def removePadding(bitSeq)
# Singature: string => string
# Purpose: Remove the padding OneAndZeroes from a bit sequence (used in decryption)
# Example: removePadding("101100011010101110000") => "1011000110101011"
# Algorithm: scan from the left to the right, removing all 0 on the way, then removing a single 1
# then stop

def removePadding(bitSeq):
       # padding is 10..00 at the end
       indexOfOne = len(bitSeq)-1
       if(indexOfOne<=0): 
              # print("Weird")
              return bitSeq
       # print("Test: ",indexOfOne)
       while bitSeq[indexOfOne]=="0":
              indexOfOne = indexOfOne -1
       return bitSeq[0:indexOfOne]


#def blocks2numberSeq(blocks):
# Singnature:  List of binary blocks => List of decimal numbers
# Purpose: Convert plain blocks into a list of decimal numbers
# Example: blocks2numberSeq(['1011000', '1101010', '1110000']) =>  [88, 106, 112]
# Algorithm: for each b in blocks, convert b into decimal
def blocks2numberSeq(blocks):
       numSeq = []
       for b in blocks:
              numSeq.append(int(b,2))
       return numSeq



# def numberSeq2Blocks(numSeq, bsize):
# Signature: list of decimal numbers x block size => list of binary blocks
# Purpose: convert number sequence into blocks. 
# Examples:   numberSeq2Blocks([88, 106, 112],7) ==> ['1011000', '1101010', '1110000']
#       numberSeq2Blocks([121, 6, 73],8) => ['01111001', '00000110', '01001001']
    

def numberSeq2Blocks(numSeq, bsize):
       blocks = []
       for num in numSeq:
              block = bin(num) # 11 ==> '0b1011'; 166 => '0b10100110'; 4 => '0b100'
              block = block[2:] # trip of 0b at begining: '0b1011'  ==> "1011"; '0b10100110' => 10100110
              if len(block)<bsize:
                     block = "0"*(bsize-len(block)) + block # add 0
              blocks.append(block)
       return blocks


#def rsaEncrypt(key, plainBitSeq):
# Signature: RSA key x String of 0/1 => String of 0/1      
# Purpose: Encrypt plainBitSeq using key = (e,n)
# Example: rsaEncrypt((77,143),"1000100110101011") ==> "011110010000011001001001"

def rsaEncrypt(key, plainBitSeq):
       (e,n) = key
       plainBlockSize = floor(log(n,2))
       cipherBlockSize =  plainBlockSize + 1
       plainBlocks = bitSeq2PlainBlocks(plainBitSeq,plainBlockSize)
       # print("plainBlocks = ", plainBlocks)
       plainNumSeq = blocks2numberSeq(plainBlocks)
       # print("plainNumSeq = ", plainNumSeq)
       # encryption
       cipherNumSeq = []
       for plainNum in plainNumSeq:
              # print(plainNum,e,n)
              cipherNum = modularExp.effModuloExp(plainNum,e,n) ## modular exponentiation using ** and % of Python
              cipherNumSeq.append(cipherNum)
       # print("cipherNumSeq = ", cipherNumSeq)
       cipherBlocks = numberSeq2Blocks(cipherNumSeq,cipherBlockSize)
       # print("cipherBlocks = ", cipherBlocks)
       cipherBitSeq = ""
       for b in cipherBlocks:
              cipherBitSeq = cipherBitSeq + b
       return cipherBitSeq



#def rsaDecrypt(key, cipherBitSeq):
# Signature: RSA key x String of 0/1 => String of 0/1         
# Purpose: Decrypt cipherBitSeq using key = (d,n)
# Example: rsaDecrypt((53,143),"011110010000011001001001") ==> "1011000110101011"


def rsaDecrypt(key, cipherBitSeq):
       (d,n) = key
       plainBlockSize = floor(log(n,2))
       cipherBlockSize =  plainBlockSize + 1
       cipherBlocks = []
       numOfCipherBlocks = floor(len(cipherBitSeq)/cipherBlockSize)
       for i in range(0,numOfCipherBlocks):
              cipherBlocks.append(cipherBitSeq[i*cipherBlockSize: (i+1)*cipherBlockSize])
              
       # print("cipherBlocks = ", cipherBlocks)
       cipherNumSeq = blocks2numberSeq(cipherBlocks)
       # print("cipherNumSeq = ", cipherNumSeq)
       # decryption
       plainNumSeq = []
       for cipherNum in cipherNumSeq:
              plainNum = modularExp.effModuloExp(cipherNum,d,n)
              # plainNum = cipherNum**d % n  ## modular exponentiation using ** and % of Python
              plainNumSeq.append(plainNum)
       # print("plainNumSeq", plainNumSeq)
       plainBlocks = numberSeq2Blocks(plainNumSeq,plainBlockSize)
       # print("plainBlocks", plainBlocks)
       plainBitSeq = ""
       for pb in plainBlocks:
              plainBitSeq = plainBitSeq + pb
       return removePadding(plainBitSeq)
