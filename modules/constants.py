import os

# -------------------- Setting Constants --------------------
SERVER_IP_ADDR = '127.0.0.1' 
SERVER_PORT_NUM = 4444

# Use the same 32-byte (64 hexadecimal characters) key as the Node.js server.
AES_ENCRYPTION_KEY =  b'Byte_format_aes_key'

# Set TEST_DIRECTORY relative to the directory where the current script is running.
# Don't use this code 
# PERSISTENCE_DIRECTORY = # If you are using the Registry, use this -> os.environ.get("ProgramFiles", r"C:\Program Files") # OR os.path.join( os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
CURRENT_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_DIRECTORY = os.path.join(CURRENT_SCRIPT_DIR, 'troycon_research_env') 

RECONNECTION_DELAY_SECONDS = 5 # Reconnection delay time when C2 server connection fails.