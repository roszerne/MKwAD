
import os
import argparse

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
        eocd_record.printEOCD()

    return eocd_record

def hide_secret(zip_file, secret_file, output_file, eocd):

    with open(zip_file, 'rb') as input_file, open(output_file, 'wb') as output_file, open(secret_file, 'rb') as secret:

        # copy all data up to first Central Directory header
        data = input_file.read(eocd.cd_offset)
        output_file.write(data)

        # copy the file we want to hide
        output_file.write(secret.read())

        # copy central directory headers
        input_file.seek(eocd.cd_offset)
        central_directory_headers = input_file.read(eocd.eocd_pos - eocd.cd_offset)
        output_file.write(central_directory_headers)
        
        # update information about Central Directory offset in EOCD
        new_eocd_offset = eocd.cd_offset + os.path.getsize('secret.txt')
        ba = bytearray(eocd.eocd)
        ba[16:20] = new_eocd_offset.to_bytes(4, 'little')
        b_new = bytes(ba)

        # copy modified eocd header
        output_file.write(b_new)


def inject_file(zip_file, secret_file, output_file = "ouput.zip"):

    # Step 1: get End Of Central Directory record from ZIP file
    eocd = parse_eocd(zip_file)

    # Step 2: Create new file and hide secret in it
    hide_secret(zip_file, secret_file, output_file, eocd)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Scrypt for hiding files in zip archive')

    parser.add_argument('zip_file', type=str,
                        help='name of the archive you want to hide a secret in')
    parser.add_argument('secret_file', type=str,
                        help='name of secret the hide')
    parser.add_argument('output_file', type=str, nargs='?', default = "output.zip",
                        help='output ZIP archive')

    args = parser.parse_args()

    #zip_file = 'test.zip'
    #secret_file = 'secret.txt'
    #output_file = "new_test.zip"
    inject_file(args.zip_file, args.secret_file, args.output_file)
    #inject_file(sys.argv[1], sys.argv[2], sys.argv[3])
