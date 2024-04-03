import json
from os.path import exists
class User:
    def __init__(self, username, password, role='regular_user'):
        self.username = username
        self.password = password
        self.role = role

    def get_role(self):
        return self.role
    def update_role(self, new_role):
        self.role = new_role
#function to save users to a JSON file
def save_users_to_json(users, filename):
    with open(filename, 'w') as file:
        json.dump(users, file)

def save_user_to_json(user, filename):
    # Load existing user data from the JSON file, if it exists
    if exists(filename):
        with open(filename, 'r') as file:
            user_data = json.load(file)
    else:
        user_data = []

    # Check if the user already exists in the data
    user_exists = False
    for existing_user in user_data:
        if existing_user["username"] == user.username:
            # Update the existing user's data
            existing_user["password"] = user.password
            existing_user["role"] = user.role
            user_exists = True
            break

    # If the user does not exist, append a new entry
    if not user_exists:
        # Convert the user object to a dictionary
        user_dict = {
            "username": user.username,
            "password": user.password,
            "role": user.role
        }
        # Append the new user data to the existing user data
        user_data.append(user_dict)

    # Serialize updated user data to JSON
    json_data = json.dumps(user_data, indent=4)

    # Write JSON data to file
    with open(filename, 'w') as file:
        file.write(json_data)

def load_users_from_json(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def update_user_role(username, new_role, filename):
    users = load_users_from_json(filename)
    for user in users:
        if user["username"] == username:
            # Update the role of the existing user
            user["role"] = new_role
            # Save the updated user data back to the JSON file
            save_users_to_json(users, filename)
            break
