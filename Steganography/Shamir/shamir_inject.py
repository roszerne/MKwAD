
import os
import argparse
from Crypto.Protocol.SecretSharing import Shamir

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

def hide_secret(zip_files, secret_file):

    shares = []
    data_secrets = []

    with open(secret_file, 'rb') as secret:

        secret_data = secret.read()
        data_secrets = [secret_data[i:i+16] for i in range(0, len(secret_data), 16)]

        #padding
        if len(data_secrets[-1]) < 16:
            data_secrets[-1] += b'2' 
            for i in range(0, 16 - len(data_secrets[-1])):
                data_secrets[-1] += b'0'

        for i in range(0, len(data_secrets)):
            shares.append(Shamir.split(2, len(zip_files), data_secrets[i]))

    for i in range(0, len(zip_files)):

        with open(zip_files[i], 'rb') as input_file: 

            eocd = parse_eocd(zip_files[i])
            # copy all data up to first Central Directory header
            data = input_file.read(eocd.cd_offset)

            input_file.seek(eocd.cd_offset)
            central_directory_headers = input_file.read(eocd.eocd_pos - eocd.cd_offset)

            # update information about Central Directory offset in EOCD
            new_eocd_offset = eocd.cd_offset + (16 * len(data_secrets)) + 4 + 1
            ba = bytearray(eocd.eocd)
            ba[16:20] = new_eocd_offset.to_bytes(4, 'little')
            b_new = bytes(ba)

            with open("out_" + zip_files[i], 'wb') as output_file:

                output_file.write(data)

                output_file.write((i + 1).to_bytes(1, 'little')) 

                for j in range (0, len(data_secrets)):
                    output_file.write(shares[j][i][1])

                #write the length of the file on 4 bytes
                output_file.write((16 * len(data_secrets)).to_bytes(4, 'little'))
                # copy central directory headers
                output_file.write(central_directory_headers)

                # copy modified eocd header
                output_file.write(b_new)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Scrypt for hiding files in zip archive')

    parser.add_argument('secret_file', type=str,
                        help='name of secret the hide')
    parser.add_argument("--archives", nargs="+", help="List of zip archives")

    args = parser.parse_args()
    
    hide_secret(args.archives, args.secret_file)

