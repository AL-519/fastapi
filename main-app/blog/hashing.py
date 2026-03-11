"""from passlib.context import CryptContext

pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Hash():
    def bcrypt(password: str):
        return pwd_cxt.hash(password)

    def verify(hashed_password,plain_password):
        return pwd_cxt.verify(plain_password,hashed_password)
    
"""
"""
import hashlib
import secrets

class Hash():
    def bcrypt(password: str):
        # 1. Create a random salt
        salt = secrets.token_hex(16)
        
        # 2. Hash the password with the salt using PBKDF2
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt.encode('utf-8'), 
            100000
        )
        
        # 3. Return a single string containing both (so your DB can store it easily)
        return f"{salt}${key.hex()}"

    def verify(hashed_password, plain_password):
        try:
            # 1. Extract the salt and the stored hash from the database string
            salt, stored_key = hashed_password.split('$')
            
            # 2. Hash the plain_password the user just typed in, using the exact same salt
            new_key = hashlib.pbkdf2_hmac(
                'sha256', 
                plain_password.encode('utf-8'), 
                salt.encode('utf-8'), 
                100000
            )
            
            # 3. Securely compare them (returns True if they match, False if not)
            return secrets.compare_digest(stored_key, new_key.hex())
        except ValueError:
            # Catches errors if the hash format in the database is invalid/old
            return False
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize the Argon2 hasher
ph = PasswordHasher()


class Hash():
    @staticmethod
    def bcrypt(password: str):
        # We keep the name 'bcrypt' so your other files don't break,
        # but it is securely hashing with Argon2 now!
        return ph.hash(password)

    @staticmethod
    def verify(hashed_password, plain_password):
        try:
            # Argon2 takes the hash first, then the plain text password
            return ph.verify(hashed_password, plain_password)
        except VerifyMismatchError:
            # Argon2 raises an error if passwords don't match.
            # We catch it and return False to mimic passlib's behavior perfectly.
            return False
        except Exception:
            # Catch-all for any other formatting errors (like old bcrypt hashes)
            return False
