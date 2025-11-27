<p align="center">
  <img src="./assets/icon/TroyCon_icon.png" alt="TroyCon icon" width="200" />
</p>

<h1 align="center">TroyCon</h1>

TroyCon is a Trojan Horse simulation tool designed solely for educational and research purposes.  
This project aims to replicate the core principles and mechanisms observed in real-world backdoor malware, including covert Command & Control (C2) communication, remote command execution, and file transfer.

> [!WARNING]  
> **This tool is intended for research purposes only.**   
> Run it exclusively in strictly isolated and controlled environments, such as a dedicated **virtual machine (VM)**.  
> Do not distribute or use this code for **malicious or illegal activities**.  
> Unauthorized use on real systems may result in legal consequences.  
> The developer assumes no responsibility for any misuse of this software or any damage it may cause.  


## Table of Contents
* [Introduction](#introduction)
* [Features](#features)
* [Project Structure](#project-structure)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Usage](#usage)
    * [1. Running the Server (Node.js)](#1-running-the-server-nodejs)
    * [2. Running the Troycon (Python)](#2-running-the-troycon-Python)
* [Contributing](#contributing)
* [LICENSE](#license)
* [Contact](#contact)

## Introduction

TroyCon is a Trojan horse simulation tool designed exclusively for educational and research purposes.  
This project replicates the core principles and mechanisms observed in real backdoor malware, including covert Command & Control (C2) communication, remote command execution, and file transfer.  
The simulation consists of a Python-based client and a Node.js-based C2 server, implementing a system that securely establishes dynamic AES-256-CBC encryption keys through Diffie-Hellman key exchange, closely mimicking real attacker environments.

## Features

* Dynamic AES-256-CBC Encrypted Communication: Establishes session keys securely via Diffie-Hellman key exchange to protect all network data with symmetric encryption.

* C2 Server Communication: Supports receiving commands and sending results via TCP sockets.

* Command Execution: Executes received shell commands within a secure test directory and returns the results.

* File Transfer: Supports file upload from client to server and file download from server to client.

* Stealth Feature: Hides the console window on Windows to minimize execution visibility.

* Persistence: Replicates the client executable within the test directory for re-execution.

* Working Directory Restriction: All file and command operations are confined to a designated safe directory.

* Automatic Reconnection: Retries connection to the C2 server at regular intervals upon failure.


## Project Structure
``` bash
EchoCrypt/
├── main.py   
├── AES_KEY.py // This code is no longer necessary.
├── modules/
│   ├── troycon.py 
│   ├── constants.py 
│   └── __init__.py         
└── c2_server.js
``` 

## Prerequisites

* Python 3.10+
* `pip` (Python package installer)
* Node.js 22.16+
* `npm` (Node Package Manager)

## Installation

1.  **Clone the repository:** (If this is from a GitHub repo)
    ```bash
    git clone https://github.com/Quema100/TroyCon.git
    cd TroyCon
    ```
    (If you received the files directly, just navigate to the project directory.)

2.  **Install dependencies:**
    ```bash
    pip install cryptography 
    ```
## Usage

### 1. Running the Server (Node.js)

To launch the C2 server, run:

```bash
npm start
```

The server is capable of handling multiple clients simultaneously, managing command transmission and file uploads/downloads in an encrypted state.  
To interact with a client, you can input commands in the following format via the terminal:  

```bash
[client_address] dir
[client_address] GET_FILE /path/to/file.txt
[client_address] PUT_FILE /path/to/local_file.txt /path/to/directory/remote_file.txt
```

### 2. Running the Troycon (Python)

Run the Python client script:

```bash
python main.py
```

The client connects to the C2 server using the AES key you generated, executing commands, uploading/downloading files, and maintaining stealth and persistence within a specified test directory.  

> [!TIP]
> **How to run this program on another PC**  
>  To run this program on another PC, follow these simple steps:  
>   1. install pyinstaller:
>       ``` ps
>       pip install pyinstaller
>       ```
>   2. Build:
>      ``` ps
>      pyinstaller -w -F -n=TroyCon --icon=./assets/icon/TroyCon_icon.ico main.py
>      ```

## Contributing

Feel free to fork this repository, open issues, and submit pull requests. Suggestions for improving realism, or code quality are welcome.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions or discussions related to this simulation, please open an issue in the GitHub repository.