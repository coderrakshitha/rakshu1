password = input("Enter your password: ")  # Accept user input
import re

def evaluate_password_strength(password):
    # Criteria for password strength
    if len(password) < 8:
        return "Weak: Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Weak: Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Weak: Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Weak: Password must include at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Weak: Password must include at least one special character."
    return "Strong: Your password is secure."

feedback = evaluate_password_strength(password)
print(feedback)
import os

def generate_salt():
    return os.urandom(16)  # Generates a 16-byte salt

salt = generate_salt()
print(f"Salt (hex): {salt.hex()}")  # Display the salt in hexadecimal format
import hashlib

def hash_password(password, salt):
    # Combine password and salt and hash using SHA-256
    password_bytes = password.encode('utf-8')  # Convert password to bytes
    salted_password = password_bytes + salt  # Combine password and salt
    return hashlib.sha256(salted_password).hexdigest()  # Generate the hash

hashed_password = hash_password(password, salt)
print(f"Hashed Password: {hashed_password}")
print("Your password has been securely hashed and salted.")
def rehash_password(stored_password, current_hash, new_salt):
    new_hash = hash_password(stored_password, new_salt)
    if current_hash != new_hash:
        print("Password rehashed successfully with the new salt.")
    else:
        print("Error: New hash matches the old hash (unexpected).")
    return new_hash

new_salt = generate_salt()  # Generate a new salt for rehashing
rehash = rehash_password(password, hashed_password, new_salt)
print(f"New Hashed Password: {rehash}")
