import json
import uuid
from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

USERS_FILE = "users.json"
SHADOWS_FILE = "shadows.txt"

ph = PasswordHasher()

#Function to load users
def load_users():
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

#Function to save users
def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def main():
    print("1. Login")
    print("2. Register")

    choice = input("Choose an option (1 or 2): ")

    if choice == "1": #Login
        #Inputs for username
        Username = input("Username: ")
        Password = input("Password: ")

        #Loads shadows.txt
        shadows = {}
        try:
            with open(SHADOWS_FILE, "r") as f:
                for line in f:
                    shadow_username, hashed_password = line.strip().split(":", 1)
                    shadows[shadow_username] = hashed_password
        except FileNotFoundError:
            pass

        #Checks if username is in shadows.txt
        if Username not in shadows:
            print("Invalid username or password.")
        #Checks if password is correct
        else:
            try:
                ph.verify(shadows[Username], Password)
            except VerifyMismatchError:
                print("Invalid username or password.")
            #Once password check is done, updates last login time
            else:
                users = load_users()
                for user in users:
                    if user["username"] == Username:
                        user["last_login"] = datetime.now(timezone.utc).isoformat()
                        break
                save_users(users)

                print("Login successful!")

                #USER IS LOGGED IN, WRITE CODE HERE DANIEL!!!!!!




    elif choice == "2": #Register
        Username = input("Choose a username: ")
        Password = input("Choose a password: ")
        Display_Name = input("Choose a display name: ") #This is not used for login

        #Load users.json
        users = load_users()
        #Username check
        if any(user["username"] == Username for user in users):
                    print("That username is already taken.")
        #Displayname check
        elif any(user["display_name"] == Display_Name for user in users):
                    print("That display name is already taken.")
        else:
            #Getting time
            now = datetime.now(timezone.utc).isoformat()
            #Creating array for user
            new_user = {
                "username": Username,
                "user_id": str(uuid.uuid4()), #This library *should* make a unique ID
                "display_name": Display_Name,
                "created_at": now,
                "last_login": now, #Leaving this empty might break it so I just set it too created_at time just in case
            }

            #Appends the array to the json file then saves it.
            users.append(new_user)
            save_users(users)

            with open(SHADOWS_FILE, "a") as f: #Opens shadows.txt
                f.write(f"{Username}:{ph.hash(Password)}\n") #apprends username, then the hashed password using Argon2 (which also hashes)

            print("Account created successfully.")
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()