import os
import binascii

aes_key_bytes = os.urandom(32)
aes_key_hex = binascii.hexlify(aes_key_bytes).decode('ascii')
print("--- Generated AES Key ---")
print(f"Byte format: b'{aes_key_bytes.decode('latin-1').encode('unicode_escape').decode('ascii')}'")
print(f"Hexadecimal format: '{aes_key_hex}'")
print("--------------------")