import socket
import importlib

ecdh = importlib.import_module("1905050_ECDH")
aes = importlib.import_module("1905050_AES")

port = 12345
host = "127.0.0.1"

def calculateSharedKey(B, other_public_key):
    return B.extract_key(B.get_shared_key(other_public_key))

def keyRound(sharedKey):
    # convert sharedKey to string
    sharedKey = str(sharedKey)
    keyStateMatrix = aes.buildKeyMatrix(sharedKey, 4)
    roundKeys = aes.scheduleKey(keyStateMatrix, 11, 4)
    roundKeys = aes.generateRoundKeys(roundKeys, 11)

    return roundKeys

def encrypt(plaintext, roundKeys):
    blocks = aes.generateBlocks(plaintext)
    plainTextMatrix = aes.buildBlockMatrix(blocks)
    IV = aes.generateIV()
    cipherTextMatrix = aes.encrypt(plainTextMatrix, roundKeys, IV)

    return cipherTextMatrix

def decrypt(ciphertext, roundKeys):
    blocks = aes.generateBlocks(ciphertext)
    cipherTextMatrix = aes.buildBlockMatrix(blocks)
    plainText = aes.decrypt(cipherTextMatrix, roundKeys)

    return plainText


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)

    Bob, addr = s.accept()
    print("Connected to Alice")

    # Receive length of info of concatenated values of a, b, p, G.x, G.y, pub_key.x, pub_key.y
    length = Bob.recv(1024).decode()

    # Receive info of concatenated values of a, b, p, G.x, G.y, pub_key.x, pub_key.y
    data = Bob.recv(int(length)).decode()
    data = data.split(" ")
    a = int(data[0])
    b = int(data[1])
    p = int(data[2])
    G = ecdh.Point(int(data[3]), int(data[4]))
    pub_key_Alice = ecdh.Point(int(data[5]), int(data[6]))

    # ECDH
    B = ecdh.ECDH(a, b, p, G)
    pub_key_Bob = B.get_public_key(B.private_key)

    # String representation of public key of Bob
    pub_key_Bob_string = str(pub_key_Bob.x) + " " + str(pub_key_Bob.y)

    # Send public key of Bob
    Bob.sendall(pub_key_Bob_string.encode())

    sharedKey = calculateSharedKey(B, pub_key_Alice)
    print("Shared Key: " + str(sharedKey))
    roundKeys = keyRound(sharedKey)


    # AES
    while True:
        # Receive ciphertext
        message = Bob.recv(1024).decode()
        plainText = decrypt(message, roundKeys)

        if plainText == "exit":
            break

        print("CipherText received : " + message)
        print("Alice: " + plainText)

        # Send ciphertext
        message = input("Bob: ")

        cipherText = encrypt(message, roundKeys)
        print("CipherText sent : " + cipherText)
        Bob.sendall(cipherText.encode())

        if message == "exit":
            break


    Bob.close()
    s.close()


if __name__ == "__main__":
    main()