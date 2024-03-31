import socket
import threading
from cryptography.fernet import Fernet
import rsa
from tkinter import Tk, Frame, Scrollbar, Text, Entry, Button, END

# Create a TCP/IP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the server address and port
HOST = '127.0.0.1'
PORT = 1234
server_address = (HOST, PORT)

# Connect to the server
try:
    client_socket.connect(server_address)
except Exception as e:
    print(f"Error connecting to the server: {e}")
    exit()

public_key, private_key = rsa.newkeys(1024)


with open("public_client.pem", "wb") as f:
    f.write(public_key.save_pkcs1("PEM"))

with open("private_client.pem", "wb") as f:
    f.write(private_key.save_pkcs1("PEM"))

with open("public_server.pem", "rb") as f:
    public_key_server = rsa.PublicKey.load_pkcs1(f.read())

# Function to encrypt a message
def encrypt_message(message):
    # Encrypt message using RSA public key
    encrypted_message = rsa.encrypt(message.encode('utf-8'), public_key_server)
    return encrypted_message

# Function to decrypt a message
def decrypt_message(encrypted_message, fernet_key):
    fernet = Fernet(fernet_key)
    decrypted_message = fernet.decrypt(encrypted_message)
    return decrypted_message.decode()

# Function to receive and decrypt messages
# Function to receive and decrypt messages
def receive_messages():
    while True:
        try:
            # Receive message from the server
            message = client_socket.recv(1024)

            # Check if the message is encrypted
            if message.startswith(b'[encrypted]'):
                # Remove the '[encrypted]' prefix
                message = message[len(b'[encrypted]'):]

                # Decrypt the message using the Fernet key
                decrypted_message = decrypt_message(message)

                # Print the decrypted message
                print(decrypted_message)
            else:
                # Print the plaintext message
                print(message.decode())

        except Exception as e:
            print(f"Error receiving message: {e}")
            break


def display_message(message):
    chat_history.config(state='normal')
    chat_history.insert(END, message + '\n')
    chat_history.config(state='disabled')
    chat_history.yview(END)
# Function to send a message
def send_message():
    while True:
        try:
            message = entry_field.get()
            if message:
                entry_field.delete(0, END)
                client_socket.send(encrypt_message(message))


        except Exception as e:
            print(f"Error sending message: {e}")
            break

def join_chat():
    try:

        # Get user input for the chat room name
        room_name = input()

        # Send the chat room name to the server
        client_socket.send(room_name.encode())

        # Receive response from the server
        response = client_socket.recv(1024).decode().strip()

        # Print the server's message
        print(response)

    except Exception as e:
        print(f"Error joining chat: {e}")


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
            client_socket.send(f'/send_file {file_name}'.encode())
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

# Start the send and receive threads
send_thread = threading.Thread(target=send_message)
receive_thread = threading.Thread(target=receive_messages)
send_thread.start()
receive_thread.start()

# Wait for the threads to finish
send_thread.join()
receive_thread.join()

print('You are now disconnected from the server')

def create_gui():
    root = Tk()
    root.title("Chat Client")

    frame = Frame(root)
    scrollbar = Scrollbar(frame)
    global chat_history
    chat_history = Text(frame, height=20, width=50, state='disabled', yscrollcommand=scrollbar.set)
    global entry_field
    entry_field = Entry(frame, width=50)
    send_button = Button(frame, text="Send", command=send_message)

    frame.pack(pady=10)
    scrollbar.pack(side='right', fill='y')
    chat_history.pack(side='left', fill='both', padx=5, pady=5)
    entry_field.pack(side='left', fill='x', padx=5, pady=5)
    send_button.pack(side='right', padx=5, pady=5)

    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()

    root.mainloop()

if authenticate_user():
    print('You are now connected to the server!')
else:
    print('Failed to connect to the server')
    client_socket.close()
    exit()

create_gui()