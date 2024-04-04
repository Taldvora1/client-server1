import socket
import threading
import time

from cryptography.fernet import Fernet
import rsa

MAX_FILE_SIZE = 20000000
# Create a TCP/IP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the server address and port
HOST = '127.0.0.1'
PORT = 1234
server_address = (HOST, PORT)

# Global flag to indicate if receiving should be paused
receiving_paused = False

# Connect to the server
try:
    client_socket.connect(server_address)
except Exception as e:
    print(f"Error connecting to the server: {e}")
    exit()

key = Fernet.generate_key()

# Save the key to a file
def save_key():
    with open('key.key','wb') as file:
        file.write(key)


# Load the key from the file
def load_key():
    return open('key.key', 'rb').read()


# Try to load key from file if doesn't exist generate a new key and save it to a file
def load_or_generate_key():
    try:
        return load_key()
    except FileNotFoundError:
        save_key()
        return load_key()


def encrypt_message(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())


def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()

def send_message():
    global receiving_paused

    while True:
        try:
            # Get user input for sending a message
            message = input("Enter message: ")
            if message == 'send file':
                send_file()
            elif message == 'exit':
                client_socket.send(message.encode())
            elif message == 'change password':
                receiving_paused = True  # Pause receiving
                change_password()
                receiving_paused = False  # Resume receiving after sending message
            elif message == 'create chat room':
                receiving_paused = True  # Pause receiving
                create_chat_room()
                receiving_paused = False  # Resume receiving after sending message
            elif message == 'join':
                receiving_paused = True  # Pause receiving
                client_socket.settimeout(20)
                join_chat()
                receiving_paused = False  # Resume receiving after sending message
            elif message == 'leave':
                receiving_paused = True  # Pause receiving
                client_socket.settimeout(20)
                leave_chat()
                receiving_paused = False  # Resume receiving after sending message
            else:
                # Encrypt the message using server's public key
                encrypted_message = encrypt_message(message,key)
                # Send the encrypted message to the server
                client_socket.send(encrypted_message)


        except Exception as e:
            print(f"Error sending message: {e}")
            break

# Function to receive and decrypt messages
def receive_message():
    global receiving_paused
    while True:
                if not receiving_paused:
                    client_socket.settimeout(0.5)
                    try:
                        response = client_socket.recv(1024).decode()
                        # Check if the response is empty
                        if response == '':
                            continue
                        # Check if its server message or from another user (which is encrypted)
                        if response.startswith('[server]'):
                            # Check if the response is a file
                            if '[Send the file]' in response:
                                print(response)
                                # Get the file name
                                file_name = response.split('[Send the file] ')[1][:-1]
                                # Get the file data
                                file_data = client_socket.recv(MAX_FILE_SIZE)
                                # Write the file data to a file
                                with open('sent_' + file_name, 'wb') as file:
                                    file.write(file_data)
                                print(f'File {file_name} received')
                            else:
                                print(response[len('[server] '):])
                        else:
                            # Decrypt the message
                            response = decrypt_message(response, key)
                            print(response)
                    except socket.timeout:
                        continue

def change_password():
    client_socket.send('change password'.encode())
    old_password = client_socket.recv(2048).decode()
    print(old_password)
    old_password_input = input('old password:')
    client_socket.send(old_password_input.encode())
    response = client_socket.recv(2048).decode()
    print(response)
    if response == '[server] The password is incorrect':
        return
    new_password_input = input('new password:')
    client_socket.send(new_password_input.encode())
    response = client_socket.recv(2048).decode()
    print(response)
def join_chat():
    try:
        # Send a request to join a chat room
        client_socket.send('join chat'.encode())

        # Receive instructions from the server
        response = client_socket.recv(1024).decode()
        print(response)

        # Enter the name of the chat room to join
        room_name_input = input('Room name: ')
        client_socket.send(room_name_input.encode())
        time.sleep(0.3)
        # Receive a response from the server
        response = client_socket.recv(1024).decode()
        print(response)

    except Exception as e:
        print(f"Error joining chat: {e}")

def leave_chat():
    client_socket.send('leave chat'.encode())
    response = client_socket.recv(1024).decode()
    print(response)

def create_chat_room():
    client_socket.send('create chat room'.encode())
    get_name = client_socket.recv(1024).decode()
    print(get_name)
    room_name_input = input('Room name:')
    client_socket.send(room_name_input.encode())
    response = client_socket.recv(1024).decode()
    if response == f'[server] The chat room "{room_name_input}" already exist, try again':
        print(response)
    print(response)

def authenticate_user():
    try:
        response = client_socket.recv(1024).decode().strip()
        print(response)
        choice = input()
        client_socket.send(choice.encode())
        if choice == '1':
            get_username = client_socket.recv(1024).decode().strip()
            print(get_username)
            username = input()
            client_socket.send(username.encode())
            get_password = client_socket.recv(1024).decode().strip()
            print(get_password)
            password = input()
            client_socket.send(password.encode())
            response = client_socket.recv(1024).decode().strip()
            print(response)
        elif choice == '2':
            get_username = client_socket.recv(1024).decode().strip()
            print(get_username)
            username = input()
            client_socket.send(username.encode())
            get_password = client_socket.recv(1024).decode().strip()
            print(get_password)
            password = input()
            client_socket.send(password.encode())

        # Receive response from the server
        response = client_socket.recv(1024).decode().strip()

        if response == '[server] connected!':
            return True
        else:
            print("Authentication failed.")
            return False

    except Exception as e:
        print(f"Error in authentication: {e}")
        return False

def send_file():
    file_path = input("Enter the file path: ")
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
            file_name = file.name.split('/')[-1]
            # Give more timeout for sending files
            client_socket.settimeout(5)
            # Send the file name and data to the server
            client_socket.send(f'send file {file_name}'.encode())
            client_socket.send(file_data)
            # Wait for the server to process the file and send a response
            response = client_socket.recv(1024).decode()
            # Reset the timeout
            client_socket.settimeout(0.3)
            print(response, end='')
    except FileNotFoundError:
        print("File not found")
    except Exception as e:
        print(f"Error occurred while sending file: {str(e)}")

if authenticate_user():
    print('You are now connected to the server!')
else:
    print('Failed to connect to the server')
    client_socket.close()
    exit()

# Load or generate the key
key = load_or_generate_key()
# Start the send and receive threads
send_thread = threading.Thread(target=send_message)
receive_thread = threading.Thread(target=receive_message)
send_thread.start()
receive_thread.start()

# Wait for the threads to finish
send_thread.join()
receive_thread.join()

print('You are now disconnected from the server')
