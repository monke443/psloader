from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import argparse

AES_KEY = bytes([
    0x90, 0xAB, 0xCD, 0x12, 0x34, 0x56, 0x78, 0x9A,
    0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55
])

AES_IV = bytes([
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
    0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90
])

def encrypt_file(input_path, output_path):
    with open(input_path, 'rb') as f:
        data = f.read()

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_data = pad(data, AES.block_size) 
    encrypted = cipher.encrypt(padded_data)

    with open(output_path, 'wb') as f:
        f.write(encrypted)

    print(f"[+] Encrypted {input_path} → {output_path} ({len(encrypted)} bytes)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("-o", "--output", default="magic_bytes.enc")
    args = parser.parse_args()

    encrypt_file(args.input, args.output)
