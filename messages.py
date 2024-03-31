import json

# Function to save messages to a JSON file
def save_messages_to_json(messages, filename):
    with open(filename, 'w') as file:
        json.dump(messages, file)

# Function to load messages from a JSON file
def load_messages_from_json(filename):
    try:
        with open(filename, 'r') as file:
            file_contents = file.read()
            if file_contents:
                messages = json.loads(file_contents)
            else:
                messages = {}  # Initialize an empty dictionary
        return messages
    except FileNotFoundError:
        return {}  # Return an empty dictionary if the file doesn't exist