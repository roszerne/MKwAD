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
        #eocd_record.printEOCD()

    return eocd_record

def extract_secret(zip_file, output_file, byte_offset, eocd):

    with open(zip_file, 'rb') as input_file, open(output_file, 'wb') as output_file:

        input_file.seek(eocd.cd_offset)

        data = []

        for i in range(0, eocd.total_num_of_cd_records):
            input_file.read(28)
            n = int.from_bytes(input_file.read(2), byteorder='little')
            m = int.from_bytes(input_file.read(2), byteorder='little')
            k = int.from_bytes(input_file.read(2), byteorder='little')
            input_file.read(12 + n + m)
            data.extend(input_file.read(k))

        incremented_bytes = bytes((byte - byte_offset) % 256 for byte in data)
        output_file.write(incremented_bytes)

def extract_file(zip_file, output_file, byte_offset = 0):

    # Step 1: get End Of Central Directory record from ZIP file
    eocd = parse_eocd(zip_file)

    # Step 2: Create new file and hide secret in it
    extract_secret(zip_file, output_file, byte_offset, eocd)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Scrypt for hiding files in zip archive')

    parser.add_argument('zip_file', type=str,
                        help='name of the archive you want to extract the secret from')
    parser.add_argument('output_file', type=str,
                        help='output secret file')
    parser.add_argument('byte_offset', type=int, nargs='?', default = 0,
                    help='bytes offset of secret file')

    args = parser.parse_args()

extract_file(args.zip_file, args.output_file, args.byte_offset)
