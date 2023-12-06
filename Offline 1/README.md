
# Cryptography Implementations

This repository includes independent implementations of cryptographic algorithms in Python.

## Task 1: Independent Implementation of 128-bit AES

### Overview
- The program encrypts and decrypts text blocks using the Advanced Encryption Standard (AES).
- Supports variable key sizes and uses CBC with PKCS#7 padding for text input.

### Execution
1. **Key Scheduling Algorithm**
   - Generate a key provided by the user (ASCII string) with a length of 128 bits or other sizes.
   - Implement the key scheduling algorithm.
   
2. **Encryption**
   - Encrypt text blocks of 128 bits with the generated keys.
   - Handle text longer than 128 bits by dividing it into chunks.

3. **Decryption**
   - Decrypt the encrypted text blocks and compare with the original text.

4. **Padding Scheme**
   - Utilizes PKCS#7 for proper padding to manage file content not aligned to the block size.

5. **Performance Reporting**
   - Report time-related performance within the code.

### Sample Input/Output
Provide examples of input data, encryption, and decryption processes along with the expected output.

## Task 2: Independent Implementation of Elliptic Curve Diffie-Hellman

### Overview
- Implements Elliptic Curve Diffie-Hellman key exchange using Python.
- Generates shared parameters, computes scalar multiplication, and calculates shared keys.

### Execution
1. **Shared Parameter Generation**
   - Generate parameters G, a, b, and P for the elliptic curve, adhering to NIST standards.

2. **Key Exchange**
   - Perform scalar multiplication with generated points for both Alice (Ka * G mod P = A) and Bob (Kb * G mod P = B).

3. **Shared Key Calculation**
   - Compute R = Ka * Kb * G mod P, applying modular arithmetic and Fermat's theorem.

4. **Performance Measurement**
   - Report time-related performance averaged over multiple trials for various key sizes (128, 192, 256 bits).

## Implementation of the Whole Cryptosystem

### Overview
Demonstrates a cryptosystem using TCP Socket Programming between Alice (sender) and Bob (receiver).

1. **Key Exchange**
   - ALICE sends a, b, g, and Ka * g (mod p) to BOB.
   - BOB computes Kb * g (mod p) and sends it to ALICE.
   - Both compute the shared secret key and acknowledge readiness for transmission.
   
2. **Transmission**
   - ALICE sends AES encrypted ciphertext (CT) to BOB using sockets.
   - BOB decrypts the received ciphertext using the shared secret key.

### Bonus Tasks
1. **Support for Different File Types**
   - Modify AES to handle various file types (image, pdf, etc.) with proper padding besides text files.
   
2. **Key Size Generalization**
   - Extend AES implementation to support 192 and 256-bit keys.
