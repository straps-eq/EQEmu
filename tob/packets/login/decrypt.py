import argparse
from Crypto.Cipher import DES

def decrypt_hex_string(hex_data):
    raw_hex = "".join(hex_data).replace(" ", "")
    
    try:
        encrypted_bytes = bytes.fromhex(raw_hex)
    except ValueError:
        return "Error: Input is not valid hexadecimal."

    key = b'\x00' * 8
    iv = b'\x00' * 8
    
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    
    return decrypted_bytes

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt EQ Default Encryption.")
    parser.add_argument("data", nargs="+", help="The data hex string to decrypt")
    args = parser.parse_args()
    result = decrypt_hex_string(args.data)

print("--- Decrypted Data ---")
print(f"Data: {result.hex(' ').upper()}")