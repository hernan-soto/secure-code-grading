import binascii
import random
import secrets
import hashlib
import os
import bcrypt

class Random_generator:

    # generates a random token
    def generate_token(self, length=8, alphabet=(
    '0123456789'
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 
    )):
        # Use secrets instead of random for better slightly security
        return ''.join(secrets.choice(alphabet) for i in range(length))

    # generates salt
    def generate_salt(self, rounds=22):
        # Use bcrypt library to generate the salt
        return bcrypt.gensalt(14) 

class SHA256_hasher:

    # produces the password hash by combining password + salt because hashing
    def password_hash(self, password, salt):
        password = binascii.hexlify(hashlib.sha256(password.encode()).digest())
        password_hash = bcrypt.hashpw(password, salt)
        return password_hash.decode('ascii')

    # verifies that the hashed password reverses to the plain text version on verification
    def password_verification(self, password, password_hash):
        password = binascii.hexlify(hashlib.sha256(password.encode()).digest())
        password_hash = password_hash.encode('ascii')
        return bcrypt.checkpw(password, password_hash)

class MD5_hasher:
    
    # same as above but using a different algorithm to hash which is MD5
    def password_hash(self, password):
        return hashlib.md5(password.encode()).hexdigest()

    def password_verification(self, password, password_hash):
        password = self.password_hash(password)
        return secrets.compare_digest(password.encode(), password_hash.encode())    

# a collection of sensitive secrets necessary for the software to operate
PRIVATE_KEY = os.environ.get('PRIVATE_KEY')
PUBLIC_KEY = os.environ.get('PUBLIC_KEY')
SECRET_KEY = 'TjWnZr4u7x!A%D*G-KaPdSgVkXp2s5v8' # Should this be an environment variable too?
PASSWORD_HASHER = 'SHA256_hasher' # SHA256 is more secure than MDS (https://docs.python.org/3/library/hashlib.html)
