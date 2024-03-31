import json
from os.path import exists
class User:
    def __init__(self, username, password, role='regular_user'):
        self.username = username
        self.password = password
        self.role = role

#function to save users to a JSON file
def save_users_to_json(users, filename):
    # Load existing user data from the JSON file, if it exists
    try:
        with open(filename, 'r') as file:
            existing_users = json.load(file)
    except FileNotFoundError:
        existing_users = []

    # Append new user data to the existing user data
    for user in users:
        user_dict = {
            "username": user.username,
            "password": user.password,
            "role": user.role
        }
        existing_users.append(user_dict)

    # Serialize user data to JSON
    json_data = json.dumps(existing_users, indent=4)

    # Write JSON data to file
    with open(filename, 'w') as file:
        file.write(json_data)

def save_user_to_json(user, filename):
    # Load existing user data from the JSON file, if it exists
    if exists(filename):
        with open(filename, 'r') as file:
            user_data = json.load(file)
    else:
        user_data = []

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