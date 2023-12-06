import base64
import random as rand

import numpy as np
import time as t
import math
from BitVector import *

word_size = 8
block_size = 16

# S-Box
sbox = np.array((
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
), dtype=np.uint8)

# Inverse S-Box
inv_sbox = np.array((
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
), dtype=np.uint8)

# Rcon
rcon = np.array((
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
), dtype=np.uint8)

# Mix Column Matrix
mixColMatrix = np.array((
    (0x02, 0x03, 0x01, 0x01),
    (0x01, 0x02, 0x03, 0x01),
    (0x01, 0x01, 0x02, 0x03),
    (0x03, 0x01, 0x01, 0x02),
), dtype=np.uint8)

# Inverse Mix Column Matrix
invMixColMatrix = np.array((
    (0x0E, 0x0B, 0x0D, 0x09),
    (0x09, 0x0E, 0x0B, 0x0D),
    (0x0D, 0x09, 0x0E, 0x0B),
    (0x0B, 0x0D, 0x09, 0x0E),
), dtype=np.uint8)

AES_modulus = BitVector(bitstring='100011011')

def convertToHex(string):
    # Convert string to hex

    hexStr = ''
    for char in string:
        hexStr += hex(ord(char))[2:]
        # Add space between each byte
        hexStr += ' '

    return hexStr

def add_pkcs7_padding(data):
    # Add PKCS7 padding to the data
    padding_length = block_size - (len(data) % block_size)
    data += chr(padding_length) * padding_length

    return data

def remove_pkcs7_padding(data):
    # Remove PKCS7 padding from the data
    padding_length = ord(data[-1])
    data = data[:-padding_length]

    return data

def buildKeyMatrix(keyStr, wordCount):
    # Build key matrix from the key
    keyMatrix = np.zeros((4, wordCount), dtype=np.uint8)

    total_bytes = wordCount*4
    # need padding if keyStr is less than 16 bytes
    if len(keyStr) < total_bytes:
        keyStr += '\0'*(total_bytes-len(keyStr))

    for i in range(4):
        for j in range(wordCount):
            # convert string to hex
            keyMatrix[j][i] = ord(keyStr[i*4+j])
    return keyMatrix

def buildStateMatrix(keyStr):
    # Build state matrix from the key
    keyStateMatrix = np.zeros((4, 4), dtype=np.uint8)

    # need padding if keyStr is less than 16 bytes
    if len(keyStr) < 16:
        # keyStr += '\0'*(16-len(keyStr))
        keyStr = add_pkcs7_padding(keyStr)

    for i in range(4):
        for j in range(4):
            # convert string to hex
            keyStateMatrix[j][i] = ord(keyStr[i*4+j])

    return keyStateMatrix

def buildBlockMatrix(blockStr):
    # Build state matrix from each block of the plaintext
    for i in range(len(blockStr)):
        blockStr[i] = buildStateMatrix(blockStr[i])
    return blockStr


def g(lastCol, rconIndex):
    # g function
    # rotate the last column
    lastCol = np.roll(lastCol, -1)
    # substitute the last column
    for i in range(4):
        lastCol[i] = sbox[lastCol[i]]
    # xor with rcon
    lastCol[0] = lastCol[0]^rcon[rconIndex]

    return lastCol

def scheduleKey(keyMatrix, roundCount, wordCount):
    scheduleRounds = math.ceil((4*roundCount)//wordCount)

    # schedule the key
    expandedKey = np.zeros((scheduleRounds, 4, wordCount), dtype=np.uint8)
    expandedKey[0] = keyMatrix

    for i in range(1, scheduleRounds):
        prevRoundKey = expandedKey[i-1]

        lastCol = prevRoundKey[:, wordCount-1]

        for j in range(wordCount):
            # shift the last column
            if j == 0:
                expandedKey[i][:, j] = g(lastCol, i)^prevRoundKey[:, j]
            else:
                expandedKey[i][:, j] = expandedKey[i][:, j-1]^prevRoundKey[:, j]

    # Convert the expanded key to a 1D array by column by column
    roundKey = np.zeros((4*scheduleRounds*wordCount), dtype=np.uint8)

    for i in range(scheduleRounds):
        for j in range(wordCount):
            for k in range(4):
                roundKey[i*4*wordCount+j*4+k] = expandedKey[i][k][j]

    return roundKey

def generateRoundKeys(roundKey, roundCount):
    # generate round keys
    roundKeys = np.zeros((roundCount, 4, 4), dtype=np.uint8)

    for i in range(roundCount):
        for j in range(4):
            for k in range(4):
                roundKeys[i][k][j] = roundKey[i*4*4+j*4+k]

    return roundKeys



def applyCBC(plaintext, IV):
    # XOR the plaintext with the IV
    plaintext = plaintext^IV
    return plaintext

def generateBlocks(plainTextStr):
    return [plainTextStr[i:i + 16] for i in range(0, len(plainTextStr), 16)]

def addRoundKey(stateMatrix, roundKey):
    # add round key
    # return stateMatrix ^ roundKey
    for i in range(4):
        for j in range(4):
            stateMatrix[i][j] ^= roundKey[i][j]
    return stateMatrix

def subBytes(stateMatrix):
    # substitute bytes
    for i in range(4):
        for j in range(4):
            stateMatrix[i][j] = sbox[stateMatrix[i][j]]
    return stateMatrix

def shiftRows(stateMatrix):
    # shift rows
    for i in range(4):
        stateMatrix[i] = np.roll(stateMatrix[i], -i)
    return stateMatrix

def mixColumns(stateMatrix):
    # mix columns
    tempMatrix = np.zeros((4, 4), dtype=np.uint8)

    for row in range(4):
        for col in range(4):
            for i in range(4):
                bv1 = BitVector(intVal=mixColMatrix[row][i], size=8)
                bv2 = BitVector(intVal=stateMatrix[i][col], size=8)
                tempMatrix[row][col] ^= (bv1.gf_multiply_modular(bv2, AES_modulus, 8)).intValue()

    return tempMatrix


def encrypt(plainTextMatrix, roundKeys, IV):

    cipherTextMatrix = np.zeros((len(plainTextMatrix)+1, 4, 4), dtype=np.uint8)

    cipherText = ""

    initializingVector = np.zeros((4, 4), dtype=np.uint8)

    initializingVector = IV
    cipherTextMatrix[0] = IV
    cipherText = ("".join([chr(cipherTextMatrix[0][i][j]) for j in range(4) for i in range(4)]))

    for i in range(len(plainTextMatrix)):
        # round 0
        cipher_index = i+1
        plainTextMatrix[i] = applyCBC(plainTextMatrix[i], initializingVector)
        cipherTextMatrix[cipher_index] = addRoundKey(plainTextMatrix[i], roundKeys[0])

        for j in range(1, 10):
            cipherTextMatrix[cipher_index] = subBytes(cipherTextMatrix[cipher_index])
            cipherTextMatrix[cipher_index] = shiftRows(cipherTextMatrix[cipher_index])
            cipherTextMatrix[cipher_index] = mixColumns(cipherTextMatrix[cipher_index])
            cipherTextMatrix[cipher_index] = addRoundKey(cipherTextMatrix[cipher_index], roundKeys[j])

        cipherTextMatrix[cipher_index] = subBytes(cipherTextMatrix[cipher_index])
        cipherTextMatrix[cipher_index] = shiftRows(cipherTextMatrix[cipher_index])
        cipherTextMatrix[cipher_index] = addRoundKey(cipherTextMatrix[cipher_index], roundKeys[10])

        initializingVector = cipherTextMatrix[cipher_index]

        cipherText += ("".join([chr(cipherTextMatrix[cipher_index][row][col]) for col in range(4) for row in range(4)]))

    return cipherText


def invSubBytes(stateMatrix):
    # substitute bytes
    for i in range(4):
        for j in range(4):
            stateMatrix[i][j] = inv_sbox[stateMatrix[i][j]]
    return stateMatrix

def invShiftRows(stateMatrix):
    # shift rows
    for i in range(4):
        stateMatrix[i] = np.roll(stateMatrix[i], i)
    return stateMatrix

def invMixColumns(stateMatrix):
    # mix columns
    tempMatrix = np.zeros((4, 4), dtype=np.uint8)

    for row in range(4):
        for col in range(4):
            for i in range(4):
                bv1 = BitVector(intVal=invMixColMatrix[row][i], size=8)
                bv2 = BitVector(intVal=stateMatrix[i][col], size=8)
                tempMatrix[row][col] ^= (bv1.gf_multiply_modular(bv2, AES_modulus, 8)).intValue()

    return tempMatrix

def decrypt(cipherTextMatrix, roundKeys):

    plainTextMatrix = np.zeros((len(cipherTextMatrix)-1, 4, 4), dtype=np.uint8)

    plainText = ""

    initializingVector = np.zeros((4, 4), dtype=np.uint8)
    initializingVector = cipherTextMatrix[0]

    for i in range(len(cipherTextMatrix)-1):

        cipher_index = i+1

        # round 0
        plainTextMatrix[i] = cipherTextMatrix[cipher_index]
        plainTextMatrix[i] = addRoundKey(plainTextMatrix[i], roundKeys[10])

        for j in range(9, 0, -1):
            plainTextMatrix[i] = invShiftRows(plainTextMatrix[i])
            plainTextMatrix[i] = invSubBytes(plainTextMatrix[i])
            plainTextMatrix[i] = addRoundKey(plainTextMatrix[i], roundKeys[j])
            plainTextMatrix[i] = invMixColumns(plainTextMatrix[i])

        plainTextMatrix[i] = invShiftRows(plainTextMatrix[i])
        plainTextMatrix[i] = invSubBytes(plainTextMatrix[i])
        plainTextMatrix[i] = addRoundKey(plainTextMatrix[i], roundKeys[0])

        plainTextMatrix[i] = applyCBC(plainTextMatrix[i], initializingVector)
        initializingVector = cipherTextMatrix[cipher_index]

        plainText += ("".join([chr(plainTextMatrix[i][row][col]) for col in range(4) for row in range(4)]))

    # Remove trailing '\0' characters
    # plainText = plainText.rstrip('\0')
    remove_pkcs7_padding(plainText)

    return plainText


def generateIV():
    IV = np.zeros((4, 4), dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            IV[i][j] = rand.randint(0, 255)
    return IV

def read_file(file_name):
    with open(file_name, 'rb') as f:
        data = f.read()
    return data

def write_file(file_name, data):
    with open(file_name, 'wb') as f:
        f.write(data)



def main():
     # Read the input
     keyStr = input("Enter the key: ")
     plainTextStr = input("Enter the plain text: ")
     # plainTextStr = read_file("file.txt")
     # plainTextStr = base64.b64encode(plainTextStr).decode('utf-8')

     # print the input in ASCII and hex
     print("Key\nIn ASCII: ", keyStr)
     print("In HEX: ", convertToHex(keyStr))
     print("\nPlain text: ")
     print("In ASCII: ", plainTextStr)
     print("In HEX: ", convertToHex(plainTextStr))


     keyLen = len(keyStr)

     if keyLen == 16:
         roundCount = 11
         wordCount = 4
     elif keyLen == 24:
         roundCount = 13
         wordCount = 6
     elif keyLen == 32:
         roundCount = 15
         wordCount = 8

     # generate round keys

     # store start time and end time
     startTime = t.time()
     keyMatrix = buildKeyMatrix(keyStr, wordCount)
     roundKeys = scheduleKey(keyMatrix, roundCount, wordCount)
     roundKeys = generateRoundKeys(roundKeys, roundCount)
     endTime = t.time()

     key_schedule_time = endTime - startTime

     # Generate a random string of 128 bits for IV
     IV = generateIV()

     # Divide plain text into 16 bytes blocks
     blocks = generateBlocks(plainTextStr)
     plainTextMatrix = buildBlockMatrix(blocks)

     # start time and end time for encryption
     startTime = t.time()
     # encryption
     cipherText = encrypt(plainTextMatrix, roundKeys, IV)
     endTime = t.time()

     encryption_time = endTime - startTime

     # print the cipher text in ASCII and hex
     print("\nCiphered text: ")
     print("In ASCII: ", cipherText)
     print("In HEX: ", convertToHex(cipherText))

     cipherTextBlocks = generateBlocks(cipherText)
     cipherTextMatrix = buildBlockMatrix(cipherTextBlocks)


     # Decrypt the cipher text
     # start time and end time for decryption
     startTime = t.time()
     # decryption
     plainText = decrypt(cipherTextMatrix, roundKeys)
     endTime = t.time()

     decryption_time = endTime - startTime

     # print the plain text in ASCII and hex
     print("\nDeciphered text: ")
     print("In ASCII: ", plainText)
     print("In HEX: ", convertToHex(plainText))

     # write_file("decrypted.txt", base64.b64decode(plainText))

     print("Execution Time Details :")
     print("Key Schedule Time : ", key_schedule_time*1000)
     print("Encryption Time : ", encryption_time*1000)
     print("Decryption Time : ", decryption_time*1000)




if __name__ == '__main__':
    main()
