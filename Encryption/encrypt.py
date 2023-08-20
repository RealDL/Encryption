import secrets, hashlib, pickle, logging

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
logging.info('RealDL Encryption Module')

class Error(Exception):
    def __init__(self, message):
        super().__init__(logging.error(message))

class Generate_RSA:
    def __init__(self, num_bits):
        self.num_bits = num_bits
        self.p = self.generate_prime()
        self.q = self.generate_prime()
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.e = self.generate_public_exponent()
        self.d = self.generate_private_exponent()
        
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
            raise Error(f"Prime validation failed: {e}") from e 

    def generate_prime(self):
        try:
            while True:
                num = secrets.randbits(self.num_bits)
                if self.is_prime(num):
                    return num
        except Exception as e:
            raise Error(f"Prime generation failed: {e}") from e 

    def generate_public_exponent(self):
        try:
            min_e = 2 ** 16 + 1
            max_e = (1 << (self.num_bits // 2)) - 1
            while True:
                e = secrets.randbelow(max_e - min_e + 1) + min_e
                if self.gcd(e, self.phi_n) == 1:
                    return e 
        except Exception as e:
            raise Error(f"Public exponent generation failed: {e}") from e 

    def gcd(self, a, b):
        try:
            while b:
                a, b = b, a % b
            return a 
        except Exception as e:
            raise Error(f"GCD failed: {e}") from e 

    def generate_private_exponent(self):
        try:
            return pow(self.e, -1, self.phi_n)
        except Exception as e:
            raise Error(f"Private exponent generation failed: {e}") from e 

    def get_values(self):
        return self.e, self.d, self.n, self.num_bits

class Encryption_RSA:
    def __init__(self, num_bits):
        self.k0_hash = hashlib.sha256(b'0').digest()
        self.k1_hash = hashlib.sha256(b'1').digest()
        self.num_bits = num_bits

    def pad_oaep(self, message):
        try:
            message_int = int.from_bytes(message, byteorder='big')

            # Perform integer padding
            padded_message_int = (message_int << (self.num_bits // 8)) | (1 << (self.num_bits - 1))
            masked_data = padded_message_int ^ int.from_bytes(self.k0_hash, byteorder='big')
            masked_data_hashed = masked_data ^ int.from_bytes(self.k1_hash, byteorder='big')
            return masked_data_hashed
        except Exception as e:
            raise Error(f"OAEP padding failed: {e}") from e

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
            raise Error(f"UN-OAEP padding failed: {e}") from e
        
    def encrypt(self, message, public_key, n):
        try:
            message_bytes = self.serialise(message)
            padded_message = self.pad_oaep(message_bytes)
            cipher_message_int = pow(padded_message, public_key, n)
            cipher_message_bytes = self.serialise(cipher_message_int)
            return cipher_message_bytes
        except Exception as e:
            raise Error(f"Encryption failed: {e}") from e 

    def decrypt(self, cipher_message_bytes, private_key, n):
        try:
            cipher_message_int = self.unserialise(cipher_message_bytes)
            padded_message = pow(cipher_message_int, private_key, n)
            message_bytes = self.unpad_oaep(padded_message)
            message = self.unserialise(message_bytes)
            return message
        except Exception as e:
            raise Error(f"Decryption failed: {e}") from e 

    def serialise(self, data):
        try:
            return pickle.dumps(data) 
        except Exception as e:
            raise Error(f"Serialisation failed: {e}") from e 

    def unserialise(self, data):
        try:
            return pickle.loads(data)
        except Exception as e:
            raise Error(f"Unserialisation failed: {e}") from e 
      
class Generate_AES:
    def __init__(self, bits=2048):
        self.bits = bits
        self.key = self.generate_key()

    def generate_key(self):
        try:
            return secrets.token_bytes(self.bits)
        except Exception as e:
            raise Error(f"Key generation failed: {e}") from e 

class Encryption_AES:
    def __init__(self, key):
        self.key = key

    def pad(self, data):
        try:
            # Add PKCS7 padding
            padding_length = 16 - len(data) % 16
            padding = bytes([padding_length] * padding_length)
            return data + padding
        except Exception as e:
            raise Error(f"Padding failed: {e}") from e 

    def unpad(self, data):
        try:
            # Remove PKCS7 padding
            padding_length = data[-1]
            if padding_length < 1 or padding_length > 16:
                raise ValueError("Invalid padding")
            return data[:-padding_length]
        except Exception as e:
            raise Error(f"Unpadding failed: {e}") from e 

    def xor_encrypt(self, data, key):
        try:
            encrypted_data = bytearray()
            for i in range(len(data)):
                encrypted_byte = data[i] ^ key[i % len(key)]
                encrypted_data.append(encrypted_byte)
            return bytes(encrypted_data)
        except Exception as e:
            raise Error(f"XOR encryption failed: {e}") from e 

    def xor_decrypt(self, data, key):
        try:
            return self.xor_encrypt(data, key)  # XOR decryption is the same as encryption
        except Exception as e:
            raise Error(f"XOR decryption failed: {e}") from e 

    def encrypt(self, data):
        try:
            serialized_data = self.serialise(data)
            padded_data = self.pad(serialized_data)
            encrypted_data = self.xor_encrypt(padded_data, self.key)
            return encrypted_data
        except Exception as e:
            raise Error(f"Encryption failed: {e}") from e 

    def decrypt(self, encrypted_data):
        try:
            padded_data = self.xor_decrypt(encrypted_data, self.key)
            deserialized_data = self.unserialise(self.unpad(padded_data))
            return deserialized_data
        except Exception as e:
            raise Error(f"Decryption failed: {e}") from e 
    
    def serialise(self, data):
        try:
            return pickle.dumps(data) 
        except Exception as e:
            raise Error(f"Serialisation failed: {e}") from e 

    def unserialise(self, data):
        try:
            return pickle.loads(data)
        except Exception as e:
            raise Error(f"Unserialisation failed: {e}") from e 

def main():
    try:
        bits = 2048
        generate_rsa = Generate_RSA(bits)
        public_key, private_key, n, num_bits = generate_rsa.get_values()
        rsa_cipher = Encryption_RSA(num_bits)
        logging.info(f"public_key: {public_key}")
        logging.info(f"private_key: {private_key}")
        logging.info(f"n: {n}")
        logging.info(f"num_bits: {num_bits}")

        message = "Hello World."

        encrypted_message = rsa_cipher.encrypt(message, public_key, n)
        decrypted_message = rsa_cipher.decrypt(encrypted_message, private_key, n) 

        logging.info(f"Original Message: {message}")
        logging.info(f"Encrypted Message: {encrypted_message}")
        logging.info(f"Decrypted Message: {decrypted_message}\n\n")  

    except Exception as e:
        raise Error(f"Error main loop failed: {e}") from e 

def main2():
    try:
        bits = 2048
        encryption_key = Generate_AES(bits)
        key = encryption_key.key
        encryption = Encryption_AES(key)
        

        # Example data types
        data_string = "Hello, this is a secret message!"
        data_dict = {"name": "Alice", "age": 30}
        data_list = [1, 2, 3, 4, 5]
        data_int = 42
        
        encrypted_string = encryption.encrypt(data_string)
        encrypted_dict = encryption.encrypt(data_dict)
        encrypted_list = encryption.encrypt(data_list)
        encrypted_int = encryption.encrypt(data_int)
        
        decrypted_string = encryption.decrypt(encrypted_string)
        decrypted_dict = encryption.decrypt(encrypted_dict)
        decrypted_list = encryption.decrypt(encrypted_list)
        decrypted_int = encryption.decrypt(encrypted_int)
        logging.info(f"key: {encryption.key}\n\n")

        logging.info(f"Original String: {data_string}")
        logging.info(f"Encrypted String: {encrypted_string}")
        logging.info(f"Decrypted String: {decrypted_string}\n\n")
        
        logging.info(f"Original Dictionary: {data_dict}")
        logging.info(f"Encrypted String: {encrypted_dict}")
        logging.info(f"Decrypted Dictionary: {decrypted_dict}\n\n")
        
        logging.info(f"Original List: {data_list}")
        logging.info(f"Encrypted String: {encrypted_list}")
        logging.info(f"Decrypted List: {decrypted_list}\n\n")
        
        logging.info(f"Original Integer: {data_int}")
        logging.info(f"Encrypted String: {encrypted_int}")
        logging.info(f"Decrypted Integer: {decrypted_int}\n\n")
    except Exception as e:
        raise Error(f"Error main loop failed: {e}") from e 

if __name__ == "__main__":
    main2()
