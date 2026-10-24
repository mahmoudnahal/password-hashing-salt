
#Password hashing demo (Chapter 03 - User Authentication)


import hashlib
import hmac
import os
import secrets

USERS_FILE = "users.txt"
SALT_BYTES = 16  # 16 random bytes -> 32 hex characters


def generate_salt():
    """Return a random salt as a hex string."""
    return secrets.token_hex(SALT_BYTES)


def hash_password(password, salt):
    """Concatenate password + salt and return the SHA-256 hex digest."""
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()


def load_users():
    """Read users.txt and return a dict {username: (salt, hash)}."""
    users = {}
    if not os.path.exists(USERS_FILE):
        return users
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                username, salt, hashed = line.split(":")
                users[username] = (salt, hashed)
    return users


def register():
    username = input("Choose a username: ").strip()
    if not username or ":" in username or " " in username:
        print("Invalid username (spaces and ':' are not allowed).")
        return
    if username in load_users():
        print("This username is already taken.")
        return
    password = input("Choose a password: ")
    if not password:
        print("Password cannot be empty.")
        return

    salt = generate_salt()
    hashed = hash_password(password, salt)
    with open(USERS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{username}:{salt}:{hashed}\n")
    print(f"User '{username}' registered successfully.")


def login():
    username = input("Username: ").strip()
    password = input("Password: ")

    users = load_users()
    if username in users:
        salt, stored_hash = users[username]
        if hmac.compare_digest(hash_password(password, salt), stored_hash):
            print(f"Login successful. Welcome, {username}!")
            return
    print("Login failed: wrong username or password.")


def main():
    while True:
        print("\n=== Password Hashing Demo ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option, please choose 1, 2, or 3.")


if __name__ == "__main__":
    main()