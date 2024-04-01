import socket
import threading
import Users_Data
import time
import messages
import rsa

# Define rate-limiting parameters
MESSAGE_LIMIT = 5  # Maximum messages allowed per user
TIME_PERIOD = 1  # Time period in seconds
MAX_FILE_SIZE = 20000000

# Define the server address and port
server_address = ('127.0.0.1', 1234)

# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind(server_address)

# Start listening for incoming connections
server_socket.listen()

print(f"Server listening on {server_address}")

public_key, private_key = rsa.newkeys(1024)

with open("public_server.pem", "wb") as f:
    f.write(public_key.save_pkcs1("PEM"))

with open("private_server.pem", "wb") as f:
    f.write(private_key.save_pkcs1("PEM"))

def decrypt_message(data):
    clear_data = rsa.decrypt(data, private_key)
    return clear_data.decode()

client_sockets = [] #the connection client sockets

online_users={} #online users at the server

users = [] #users information

chat_rooms = {} #chat room name and the users that connected

messages_data = {} #dictionary with every group messages history

# Dictionary to track message counts and timestamps for each user
message_counts = {}  # {username: [message_count, last_message_time]}

def handle_client(client_socket):
    username = authenticate_user(client_socket)
    if not username:
        print('User authentication failed')
        client_socket.close()
        client_sockets.remove(client_socket)
        return

    print(f'User {username} authenticated successfully')

 # Main loop to handle client messages
    while True:
        try:
            # Receive message from client
            data = client_socket.recv(2048)

            if not check_rate_limit(username):
                send_server_message(client_socket, 'Rate limit exceeded. Please wait before sending more messages.')
                continue

            message = decrypt_message(data)

            if message == 'exit':
                leave_chat(client_socket, username)
                send_server_message(client_socket, f"{username} is offline")
                print(online_users)
                del online_users[username]
                client_socket.close()
                client_sockets.remove(client_socket)
            elif message == 'change password':
                change_password(client_socket, username)
            elif message == 'create chat room':
                create_chat_room(client_socket, username)
            elif message == 'join chat':
                join_chat(client_socket, username)
            elif message == 'leave chat':
                leave_chat(client_socket, username)
            elif message.startswith('/send_file'):
                receive_and_send_file(client_socket, username, message)

            else:

                room_name = get_user_room(username)

                if room_name:
                    # Forward the encrypted message directly to the recipient
                    broadcast_message(username, message, room_name)
                else:
                    send_server_message(client_socket, f"{username} is not in any chat room")

        except Exception as e:
            print(f"Error : {e}")
            leave_chat(client_socket, username)
            client_socket.close()
            client_sockets.remove(client_socket)
            break # Client closed connection

def send_server_message(client_socket, message, end=True):
    time.sleep(0.1)
    if end:
        server_message = f'[server] {message}\n'
    else:
        server_message = f'[server] {message}'
    client_socket.sendall(server_message.encode())
    print(f'Server message sent: {server_message[:-1]}')

def authenticate_user(client_socket):
    send_server_message(client_socket, 'Hello, to register choose 1, to log in choose 2 ')
    choise = client_socket.recv(2048).decode().strip()
    if choise == '1':
        username = create_user(client_socket)
        online_users[username] = client_socket
        send_server_message(client_socket, 'connected!')
        return username
    elif choise == '2':
        send_server_message(client_socket, 'Please enter your username: ')
        username = client_socket.recv(2048).decode().strip()
        send_server_message(client_socket, 'Please enter your password: ')
        password = client_socket.recv(2048).decode().strip()
        for user in users:
            if user["username"] == username and user["password"] == password:
                online_users[username] = client_socket
                send_server_message(client_socket, 'connected!')
                return username
        return False
    else:
        send_server_message(client_socket, 'invalid character ')
        return False

def check_rate_limit(username):
    """
    Check if the user has exceeded the message limit within the time period.
    """
    current_time = time.time()

    if username in message_counts:
        # Check if the time period has elapsed since the last message
        if current_time - message_counts[username][1] > TIME_PERIOD:
            # Reset message count and update timestamp
            message_counts[username] = [1, current_time]
        else:
            # Increment message count
            message_counts[username][0] += 1
            # Check if message limit exceeded
            if message_counts[username][0] > MESSAGE_LIMIT:
                return False
    else:
        # Initialize message count and timestamp for new user
        message_counts[username] = [1, current_time]

    return True

def create_user(client_socket):
    send_server_message(client_socket, 'Please choose a username: ')
    username = client_socket.recv(2048).decode().strip()
    send_server_message(client_socket, 'Please choose a password: ')
    password = client_socket.recv(2048).decode().strip()

    # Create the user object
    user = Users_Data.User(username, password)

    # Save the user to JSON
    try:
        Users_Data.save_user_to_json(user, 'users.json')
        send_server_message(client_socket, f'User {username} created successfully.')
        online_users[username] = client_socket
        return username
    except Exception as e:
        send_server_message(client_socket, f'Error creating user: {str(e)}')
        return False

def change_password(client_socket, username):
    send_server_message(client_socket, 'please enter your old password')
    old_password = client_socket.recv(2048)
    old_password = decrypt_message(old_password)
    for user in users:
        if user['username'] == username:
            if user['password'] == old_password:
                send_server_message(client_socket, 'please enter new password')
                new_password = client_socket.recv(2048)
                new_password = decrypt_message(new_password)
                user['password'] = new_password
                Users_Data.save_user_to_json(users,'users.json')
                send_server_message(client_socket, 'Your password has been changed')
                return
            send_server_message(client_socket, 'The password is incorrect')

def send_message(sender, recipient, message):
    """
    Send a message from one user to another.

    Args:
        sender (str): The username of the sender.
        recipient (str): The username of the recipient.
        message (str): The message to send.
    """
    # Code for sending messages between users\

def create_chat_room(client_socket,username):
    send_server_message(client_socket, 'please chose a room name')
    room_name_input = client_socket.recv(2048)
    room_name_input = decrypt_message(room_name_input)
    if room_name_input in chat_rooms:
        send_server_message(client_socket, f'The chat room "{room_name_input}" already exist, try again')
        create_chat_room(client_socket, username)
    for user in users:
        if user["username"] == username:
            user["role"] = 'admin'
    Users_Data.save_users_to_json(users, 'users.json')
    chat_rooms[room_name_input] = [username]

def leave_chat(client_socket, username):
    # Find the chat room where the user is present
    for room_name, users_in_room in chat_rooms.items():
        if username in users_in_room:
            # Remove the user from the chat room
            users_in_room.remove(username)

            # Inform other users in the chat room that someone has left
            for user in users_in_room:
                user_socket = online_users.get(user)
                if user_socket:
                    send_server_message(user_socket, f'{username} has left the chat room "{room_name}"')

            # Check if there are still users in the room
            if len(users_in_room) > 0:
                # Assign admin role to the first user in the list
                new_admin = users_in_room[0]
                for user in users:
                    if user["username"] == new_admin:
                        user["role"] = 'admin'
                        # Inform the new admin about their role
                        new_admin_socket = online_users.get(new_admin)
                        if new_admin_socket:
                            send_server_message(new_admin_socket, 'You are now the admin of this chat room')
                        break

            # Update the leaving user's role to 'regular_user'
            for user in users:
                if user["username"] == username:
                    user["role"] = 'regular_user'
                    break

            Users_Data.save_users_to_json(users, 'users.json')

            send_server_message(client_socket, f'You have left the chat room "{room_name}"')
            return

    # If the user is not in any chat room
    send_server_message(client_socket, 'You are not currently in any chat room')

def join_chat(client_socket, username):
    send_server_message(client_socket, 'Please enter the name of the chat room you want to join: ')
    room_name_input = client_socket.recv(2048)
    room_name_input = decrypt_message(room_name_input)

    # Check if the chat room exists
    if room_name_input in chat_rooms:
        # Disconnect the user from their current chat room, if any
        leave_chat(client_socket, username)

        # Add the user to the new chat room
        chat_rooms[room_name_input].append(username)

        # Check if the user is the only one in the chat room
        if len(chat_rooms[room_name_input]) == 1:
            # If the user is the only one, assign them the admin role
            for user in users:
                if user["username"] == username:
                    user["role"] = 'admin'
                    break
            Users_Data.save_users_to_json(users, 'users.json')
        send_server_message(client_socket, f'You have joined the chat room "{room_name_input}"')

        # Inform other users in the new chat room that someone has joined
        for user in chat_rooms[room_name_input]:
            if user != username:  # Exclude the user who just joined
                user_socket = online_users.get(user)
                if user_socket:
                    send_server_message(user_socket, f'{username} has joined the chat room')
    else:
        send_server_message(client_socket, f'The chat room "{room_name_input}" does not exist')

def receive_and_send_file(client_socket, username, message):
    # Get the file name from message
    file_name = message.split(' ')[1]

    # Receive the file data from the client
    file_data = client_socket.recv(MAX_FILE_SIZE)

    # Save the file to the server
    with open(file_name, 'wb') as file:
        file.write(file_data)

    # Print a message to the server
    print(f'File {file_name} received from user {username}')

    # Send a message to the client that the file was received
    send_server_message(client_socket, f'File {file_name} received successfully')

    # Get user chat room
    user_chat_room = None
    for chat_room, users in chat_rooms.items():
        if username in users:
            user_chat_room = chat_room
            break

    # Send the file to all users in the chat room
    if user_chat_room:
        for user in chat_rooms[user_chat_room]:
            # Don't send the message to the user who sent it
            if user == username:
                continue
            connected_user = online_users.get(user)
            if connected_user:
                # Send the file name to the user
                send_server_message(connected_user, f'{username} [{user_chat_room}]: *Send the file* {file_name}')
                # Send the file data to the user encrypted peer to peer
                connected_user.sendall(f'{file_data}'.encode())
    else:
        send_server_message(client_socket, 'You are not in a chat room. Please join a chat room to send messages')
        print(f'User {username} tried to send a message without being in a chat room')

def get_user_room(username):
    for room_name, users_in_room in chat_rooms.items():
        if username in users_in_room:
            return room_name
    return None  # User not found in any chat room

def broadcast_message(sender, encrypted_message, room_name):
    # Add the message to the chat room's message history
    if room_name not in messages_data:
        messages_data[room_name] = []
    messages_data[room_name].append({'sender': sender, 'message': encrypted_message})

    # Save messages to the JSON file
    messages.save_messages_to_json(messages_data, 'messages.json')

    # Send encrypted message to all users in the chat room
    users_in_room = chat_rooms.get(room_name, [])
    for user in users_in_room:
        if user != sender:  # Exclude sender
            user_socket = online_users.get(user)
            if user_socket:
                formatted_message = f"[{sender}]: {encrypted_message}"
                send_server_message(user_socket, formatted_message)



# Load the user data from the JSON file
users = Users_Data.load_users_from_json('users.json')

# Load the messages data from the JSON file
messages_data = messages.load_messages_from_json('messages.json')

# Load the room names data
for room_name in messages_data.keys():
    chat_rooms[room_name] = []

# Load messages from the JSON file
#messages_dict = Message.load_dict_from_json('messages.json')

# Accept incoming connections and handle clients
while True:
    client_socket, client_address = server_socket.accept()
    client_sockets.append(client_socket)
    print(f"Connection from {client_address}")
    client_sockets.append(client_socket)

    # Handle client in a new thread
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()
