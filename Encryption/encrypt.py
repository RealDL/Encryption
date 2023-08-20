import secrets, hashlib, pickle, logging

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
logging.info('RealDL Encryption Module')

class Error(Exception):
    def __init__(self, message):
        super().__init__(logging.error(message))

class RSA:
    def __init__(self, num_bits):
        self.num_bits = num_bits
        self.p = self.generate_prime()
        self.q = self.generate_prime()
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.e = self.generate_public_exponent()
        self.d = self.generate_private_exponent()
        self.k0_hash = hashlib.sha256(b'0').digest()
        self.k1_hash = hashlib.sha256(b'1').digest()

    def is_prime(self, number, k=20):
        try:
            if number <= 1:
                return False
            if number <= 3:
                return True
            if number % 2 == 0:
                return False

            # Write (number - 1) as 2^r * d
            r, d = 0, number - 1
            while d % 2 == 0:
                r += 1
                d //= 2

            # Perform the Miller-Rabin primality test for k rounds
            for _ in range(k):
                a = secrets.randbelow(number - 3) + 2  # Random number between 2 and number - 2
                x = pow(a, d, number)
                if x == 1 or x == number - 1:
                    continue
                for _ in range(r - 1):
                    x = pow(x, 2, number)
                    if x == number - 1:
                        break
                else:
                    return False
            return True
        except Exception as e:
            raise Error("Prime validation failed: " + str(e)) from e 

    def generate_prime(self):
        try:
            while True:
                num = secrets.randbits(self.num_bits)
                if self.is_prime(num):
                    return num
        except Exception as e:
            raise Error("Prime generation failed: " + str(e)) from e 

    def generate_public_exponent(self):
        try:
            min_e = 2 ** 16 + 1
            max_e = (1 << (self.num_bits // 2)) - 1
            while True:
                e = secrets.randbelow(max_e - min_e + 1) + min_e
                if self.gcd(e, self.phi_n) == 1:
                    return e 
        except Exception as e:
            raise Error("Public exponent generation failed: " + str(e)) from e 

    def gcd(self, a, b):
        try:
            while b:
                a, b = b, a % b
            return a 
        except Exception as e:
            raise Error("GCD failed: " + str(e)) from e 

    def generate_private_exponent(self):
        try:
            return pow(self.e, -1, self.phi_n)
        except Exception as e:
            raise Error("Private exponent generation failed: " + str(e)) from e 

    def pad_oaep(self, message):
        try:
            message_int = int.from_bytes(message, byteorder='big')

            # Perform integer padding
            padded_message_int = (message_int << (self.num_bits // 8)) | (1 << (self.num_bits - 1))
            masked_data = padded_message_int ^ int.from_bytes(self.k0_hash, byteorder='big')
            masked_data_hashed = masked_data ^ int.from_bytes(self.k1_hash, byteorder='big')
            return masked_data_hashed
        except Exception as e:
            raise Error("OAEP padding failed: " + str(e)) from e

    def unpad_oaep(self, padded_message):
        try:
            masked_data_hashed = padded_message
                
            # Perform integer unpadding
            masked_data = masked_data_hashed ^ int.from_bytes(self.k1_hash, byteorder='big')
            padded_message_int = masked_data ^ int.from_bytes(self.k0_hash, byteorder='big')
            message_int = ((padded_message_int - (1 << (self.num_bits - 1))) >> (self.num_bits // 8))
            message_length = (message_int.bit_length() + 7) // 8
            message = message_int.to_bytes(message_length, byteorder='big')
            return message
        except Exception as e:
            raise Error("UN-OAEP padding failed: " + str(e)) from e
        
    def encrypt(self, message, public_key):
        try:
            message_bytes = self.serialise(message)
            padded_message = self.pad_oaep(message_bytes)
            cipher_message_int = pow(padded_message, public_key, self.n)
            cipher_message_bytes = self.serialise(cipher_message_int)
            return cipher_message_bytes
        except Exception as e:
            raise Error("Encryption failed: " + str(e)) from e 

    def decrypt(self, cipher_message_bytes, private_key):
        try:
            cipher_message_int = self.unserialise(cipher_message_bytes)
            padded_message = pow(cipher_message_int, private_key, self.n)
            message_bytes = self.unpad_oaep(padded_message)
            message = self.unserialise(message_bytes)
            return message
        except Exception as e:
            raise Error("Decryption failed: " + str(e)) from e 

    def serialise(self, data):
        try:
            return pickle.dumps(data) 
        except Exception as e:
            raise Error("Serialisation failed: " + str(e)) from e 

    def unserialise(self, data):
        try:
            return pickle.loads(data)
        except Exception as e:
            raise Error("Unserialisation failed: " + str(e)) from e 

class RSACipher:
    def __init__(self,num_bits=512):
        self.rsa = RSA(num_bits) 

    def encrypt(self, plaintext, public_key):
        try:
            return self.rsa.encrypt(plaintext, public_key)
        except Exception as e:
            raise Error("Failed to return encrypted message: " + str(e)) from e 

    def decrypt(self, ciphertext_bytes, private_key):
        try:
            return self.rsa.decrypt(ciphertext_bytes, private_key) 
        except Exception as e:
            raise Error("Failed to return decrypted message: " + str(e)) from e 
        
    def get_public_key(self):
        try:
            return self.rsa.e 
        except Exception as e:
            raise Error("Failed to return public key: " + str(e)) from e 
        
    def get_private_key(self):
        try:
            return self.rsa.d 
        except Exception as e:
            raise Error("Failed to return private key: " + str(e)) from e 

def main():
    try:
        rsa_cipher = RSACipher(1024)
        public_key = rsa_cipher.get_public_key()
        private_key = rsa_cipher.get_private_key()
        logging.info(f"public_key: {public_key}")
        logging.info(f"private_key: {private_key}")

       
        message = "Hello World"

        encrypted_message = rsa_cipher.encrypt(message, public_key)
        decrypted_message = rsa_cipher.decrypt(encrypted_message, private_key) 

        logging.info(f"Original Message: {message}")
        logging.info(f"Encrypted Message: {encrypted_message}")
        logging.info(f"Decrypted Message: {decrypted_message}\n\n")

            

    except Exception as e:
        raise Error("Error main loop failed: " + str(e)) from e 

if __name__ == "__main__":
    main()
