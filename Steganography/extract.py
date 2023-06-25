import os
import argparse

class EOCD:

    def __init__ (self, eocd, eocd_pos):
        self.eocd = eocd
        self.eocd_pos = eocd_pos
        self.total_num_of_cd_records = int.from_bytes(eocd[10:12], byteorder='little')
        self.size_of_cd = int.from_bytes(eocd[12:16], byteorder='little')
        self.cd_offset = int.from_bytes(eocd[16:20], byteorder='little')

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
        eocd_record.printEOCD()

    return eocd_record

def extract_secret(zip_file, output_file, eocd):

    with open(zip_file, 'rb') as input_file, open(output_file, 'wb') as output_file:

        # get byte length of secret file
        input_file.seek(eocd.cd_offset)
        print(eocd.cd_offset)
        input_file.seek(-4, 1)
        secret_length = input_file.read(4)
        print(secret_length)
        secret_length = int.from_bytes(secret_length, 'little')
        print(secret_length)
        

        # copy all data up to first Central Directory header
        input_file.seek(-(4 + secret_length), 1)
        data = input_file.read(secret_length)
        output_file.write(data)

def extract_file(zip_file, output_file):

    # Step 1: get End Of Central Directory record from ZIP file
    eocd = parse_eocd(zip_file)

    # Step 2: Create new file and hide secret in it
    extract_secret(zip_file, output_file, eocd)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Scrypt for hiding files in zip archive')

    parser.add_argument('zip_file', type=str,
                        help='name of the archive you want to extract the secret from')
    parser.add_argument('output_file', type=str,
                        help='output secret file')

    args = parser.parse_args()

extract_file(args.zip_file, args.output_file)
