
import os
import argparse
import numpy as np
import math

class EOCD:

    def __init__ (self, eocd, eocd_pos):
        self.eocd = eocd
        self.eocd_pos = eocd_pos
        self.total_num_of_cd_records = int.from_bytes(eocd[10:12], byteorder='little')
        self.size_of_cd = int.from_bytes(eocd[12:16], byteorder='little')
        self.cd_offset = int.from_bytes(eocd[16:20], byteorder='little')
        #eocd_signature = int.from_bytes(eocd[0:4], byteorder='little')
        #eocd_num_of_cd_records = int.from_bytes(eocd[8:10], byteorder='little')
        #eocd_comment_length = int.from_bytes(eocd[20:22], byteorder='little')
        #eocd_comment = int.from_bytes(eocd[22:], byteorder='little')

    def printEOCD(self):
        print('Total number of central directory records: {}'.format(self.total_num_of_cd_records))
        print('Size of central directory (bytes): {}'.format(self.size_of_cd))
        print('Offset of start of central directory, relative to start of archive: {}'.format(self.cd_offset))
    

# funkcja zwracająca pozycję EOCD w pliku zip
def eocd_position(zip_file):
    with open(zip_file, 'rb') as f:
        data = f.read()
        eocd = b'\x50\x4b\x05\x06'  # EOCD signature
        pos = data.rfind(eocd)
        if pos == -1:
            raise ValueError('Invalid zip file')
        return pos

def parse_eocd(zip_file):

    # get position of EOCD record
    eocd_pos = eocd_position(zip_file)

    with open(zip_file, "rb") as f:

        f.seek(eocd_pos) 
        eocd = f.read() # read EOCD record

        # create new EOCD object

        eocd_record = EOCD(eocd, eocd_pos)

        # print data from EOCD
        #eocd_record.printEOCD()

    return eocd_record

def hide_secret(zip_file, secret_file, output_file, byte_offset, eocd):

    with open(zip_file, 'rb') as input_file, open(output_file, 'wb') as output_file, open(secret_file, 'rb') as secret:

        # copy all data up to first Central Directory header
        data = input_file.read(eocd.cd_offset)
        output_file.write(data)

        print(eocd.cd_offset)

        data = secret.read()
        incremented_bytes = bytes((byte + byte_offset) % 256 for byte in data)

        # Calculate the length of each split
        split_length = math.ceil(len(incremented_bytes) / eocd.total_num_of_cd_records)

        # Convert 'data' to a numpy array for easier manipulation
        split_data = [incremented_bytes[i:i+split_length] for i in range(0, len(incremented_bytes), split_length)]
        input_file.seek(eocd.cd_offset, 0)

        # copy central directory headers
        for i in range(0, eocd.total_num_of_cd_records):
            cd = input_file.read(32)
            n = int.from_bytes(cd[28: 30], byteorder='little')
            m = int.from_bytes(cd[30: 32], byteorder='little')
            k = int.from_bytes(input_file.read(2), byteorder='little')
            cd += len(split_data[i]).to_bytes(2, 'little')     
            cd += input_file.read(12 + n + m + k)
            cd += split_data[i]
            output_file.write(cd)
            
        # copy the file we want to hide
        #output_file.write(incremented_bytes)

        #write the length of the file on 4 bytes
        #output_file.write(os.path.getsize(secret_file).to_bytes(4, 'little'))
        new_eocd = input_file.read()
        print(new_eocd)
        output_file.write(new_eocd)


def inject_file(zip_file, secret_file, output_file = "ouput.zip", byte_offset = 0):

    # Step 1: get End Of Central Directory record from ZIP file
    eocd = parse_eocd(zip_file)

    # Step 2: Create new file and hide secret in it
    hide_secret(zip_file, secret_file, output_file, byte_offset, eocd)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Scrypt for hiding files in zip archive')

    parser.add_argument('zip_file', type=str,
                        help='name of the archive you want to hide a secret in')
    parser.add_argument('secret_file', type=str,
                        help='name of secret the hide')
    parser.add_argument('output_file', type=str, nargs='?', default = "output.zip",
                        help='output ZIP archive')
    parser.add_argument('byte_offset', type=int, nargs='?', default = 0,
                        help='bytes offset of secret file')

    args = parser.parse_args()

    inject_file(args.zip_file, args.secret_file, args.output_file, args.byte_offset)

