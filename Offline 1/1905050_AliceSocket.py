import socket
import importlib

ecdh = importlib.import_module("1905050_ECDH")
aes = importlib.import_module("1905050_AES")

port = 12345
host = "127.0.0.1"

def calculateSharedKey(A, other_public_key):
    return A.extract_key(A.get_shared_key(other_public_key))

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
    s.connect((host, port))

    # ECDH
    A = ecdh.ECDH(ecdh.params[128]['a'], ecdh.params[128]['b'], ecdh.params[128]['p'], ecdh.Point(ecdh.params[128]['gx'], ecdh.params[128]['gy']))
    a = A.a
    b = A.b
    p = A.p
    G = A.G
    pub_key = A.get_public_key(A.private_key)


    info = str(a) + " " + str(b) + " " + str(p) + " " + str(G.x) + " " + str(G.y) + " " + str(pub_key.x) + " " + str(pub_key.y)
    s.sendall(str(len(info)).encode())
    s.sendall(info.encode())

    # Receive public key of Bob
    data = s.recv(1024).decode()
    data = ecdh.Point(int(data.split(" ")[0]), int(data.split(" ")[1]))

    sharedKey = calculateSharedKey(A, data)
    print("Shared Key: " + str(sharedKey))
    roundKeys = keyRound(sharedKey)


    # AES
    while True:
        plaintext = input("Alice: ")

        ciphertext = encrypt(plaintext, roundKeys)
        print("CipherText sent: " + ciphertext)
        s.sendall(ciphertext.encode())

        if plaintext == "exit":
            break

        data = s.recv(1024).decode()
        plaintext = decrypt(data, roundKeys)

        if plaintext == "exit":
            break

        print("CipherText received: " + data)
        print("Bob: " + plaintext)

    s.close()




if __name__ == "__main__":
    main()