import numpy as np

__author__ = "Amit Yakovian"
"""
a visual example of how the AES encryption works on given data and key on a singe block.
"""


class EncryptAES:
    sbox = [
        "0x63", "0x7c", "0x77", "0x7b", "0xf2", "0x6b", "0x6f", "0xc5", "0x30", "0x01", "0x67", "0x2b", "0xfe", "0xd7",
        "0xab", "0x76",
        "0xca", "0x82", "0xc9", "0x7d", "0xfa", "0x59", "0x47", "0xf0", "0xad", "0xd4", "0xa2", "0xaf", "0x9c", "0xa4",
        "0x72", "0xc0",
        "0xb7", "0xfd", "0x93", "0x26", "0x36", "0x3f", "0xf7", "0xcc", "0x34", "0xa5", "0xe5", "0xf1", "0x71", "0xd8",
        "0x31", "0x15",
        "0x04", "0xc7", "0x23", "0xc3", "0x18", "0x96", "0x05", "0x9a", "0x07", "0x12", "0x80", "0xe2", "0xeb", "0x27",
        "0xb2", "0x75",
        "0x09", "0x83", "0x2c", "0x1a", "0x1b", "0x6e", "0x5a", "0xa0", "0x52", "0x3b", "0xd6", "0xb3", "0x29", "0xe3",
        "0x2f", "0x84",
        "0x53", "0xd1", "0x00", "0xed", "0x20", "0xfc", "0xb1", "0x5b", "0x6a", "0xcb", "0xbe", "0x39", "0x4a", "0x4c",
        "0x58", "0xcf",
        "0xd0", "0xef", "0xaa", "0xfb", "0x43", "0x4d", "0x33", "0x85", "0x45", "0xf9", "0x02", "0x7f", "0x50", "0x3c",
        "0x9f", "0xa8",
        "0x51", "0xa3", "0x40", "0x8f", "0x92", "0x9d", "0x38", "0xf5", "0xbc", "0xb6", "0xda", "0x21", "0x10", "0xff",
        "0xf3", "0xd2",
        "0xcd", "0x0c", "0x13", "0xec", "0x5f", "0x97", "0x44", "0x17", "0xc4", "0xa7", "0x7e", "0x3d", "0x64", "0x5d",
        "0x19", "0x73",
        "0x60", "0x81", "0x4f", "0xdc", "0x22", "0x2a", "0x90", "0x88", "0x46", "0xee", "0xb8", "0x14", "0xde", "0x5e",
        "0x0b", "0xdb",
        "0xe0", "0x32", "0x3a", "0x0a", "0x49", "0x06", "0x24", "0x5c", "0xc2", "0xd3", "0xac", "0x62", "0x91", "0x95",
        "0xe4", "0x79",
        "0xe7", "0xc8", "0x37", "0x6d", "0x8d", "0xd5", "0x4e", "0xa9", "0x6c", "0x56", "0xf4", "0xea", "0x65", "0x7a",
        "0xae", "0x08",
        "0xba", "0x78", "0x25", "0x2e", "0x1c", "0xa6", "0xb4", "0xc6", "0xe8", "0xdd", "0x74", "0x1f", "0x4b", "0xbd",
        "0x8b", "0x8a",
        "0x70", "0x3e", "0xb5", "0x66", "0x48", "0x03", "0xf6", "0x0e", "0x61", "0x35", "0x57", "0xb9", "0x86", "0xc1",
        "0x1d", "0x9e",
        "0xe1", "0xf8", "0x98", "0x11", "0x69", "0xd9", "0x8e", "0x94", "0x9b", "0x1e", "0x87", "0xe9", "0xce", "0x55",
        "0x28", "0xdf",
        "0x8c", "0xa1", "0x89", "0x0d", "0xbf", "0xe6", "0x42", "0x68", "0x41", "0x99", "0x2d", "0x0f", "0xb0", "0x54",
        "0xbb", "0x16"
    ]

    Rcon = np.array([['0x01', '0x02', '0x04', '0x08', '0x10', '0x20', '0x40', '0x80', '0x1b', '0x36']
                        , ['0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00'],
                     ['0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00'],
                     ['0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00']])

    def __init__(self, data, key):
        self.data = data
        self.key = key

    def add_round_key(self, data, round_key):
        new_data = np.copy(self.data)
        columns = round_key.shape[1]
        rows = round_key.shape[0]
        for index in range(columns):
            data_column = self.data[:, index]
            key_column = round_key[:, index]
            for value_index in range(rows):
                new_data[value_index][index] = hex(
                    int(data_column[value_index], base=16) ^ int(key_column[value_index], base=16))
        return new_data

    def galois_mult(self, a, b):
        a = int(a, base=16)
        p = 0
        hi_bit_set = 0
        for i in range(8):
            if b & 1 == 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set == 0x80:
                a ^= 0x1b
            b >>= 1
        # print(p)
        return p % 256

    def mix_column(self, column):
        temp = np.copy(column)
        new_column = np.array(['0x00', '0x00', '0x00', '0x00'])
        new_column[0] = hex(
            self.galois_mult(temp[0], 2) ^ self.galois_mult(temp[3], 1) ^ self.galois_mult(temp[2], 1) ^ self.galois_mult(temp[1], 3))
        new_column[1] = hex(
            self.galois_mult(temp[1], 2) ^ self.galois_mult(temp[0], 1) ^ self.galois_mult(temp[3], 1) ^ self.galois_mult(temp[2], 3))
        new_column[2] = hex(
            self.galois_mult(temp[2], 2) ^ self.galois_mult(temp[1], 1) ^ self.galois_mult(temp[0], 1) ^ self.galois_mult(temp[3], 3))
        new_column[3] = hex(
            self.galois_mult(temp[3], 2) ^ self.galois_mult(temp[2], 1) ^ self.galois_mult(temp[1], 1) ^ self.galois_mult(temp[0], 3))
        return new_column


    def rotate(self, matrix):
        new_matrix = np.array([])
        count = 0
        for i in range(matrix.shape[0]):
            row = matrix[i, :]
            for j in range(i):
                row = np.append(row, row[0])
                # row.append(row[j])
                row = np.delete(row, 0)
            count += 1
            new_matrix = np.append([new_matrix], [row]).reshape((count, matrix.shape[1]))
        return new_matrix

    def find_sbox_value(self, value):
        num = int(value, base=16)
        return self.sbox[num]

    def push_column_up(self, column):
        first = column[0]
        for i in range(3):
            column[i] = column[i + 1]
        column[3] = first

    def xor3(self, matrix, column, num):
        new = np.array(
            [[hex(int(matrix[:, 0][i], base=16) ^ int(column[i], base=16) ^ int(self.Rcon[:, num][i], base=16)) for i
              in range(4)]])
        return new

    def xor2(self, matrix_col, column):
        new = np.array([[hex(int(matrix_col[i], base=16) ^ int(column[i], base=16)) for i in range(4)]])
        return new

    def key_schedule(self, matrix, num):
        new_key = np.array([['0x00' for x in range(4)] for i in range(4)])
        column1 = np.copy(matrix[:, 3])
        self.push_column_up(column1)
        for index in range(4):
            column1[index] = hex(int(self.find_sbox_value(column1[index]), base=16))
        new_key[:, 0] = self.xor3(matrix, column1, num)
        for c in range(1, 4):
            new_key[:, c] = self.xor2(matrix[:, c], new_key[:, c - 1])

        return new_key

    def sub_bytes(self, data):
        for i in range(4):
            for index in range(4):
                data[i, index] = self.find_sbox_value(data[i, index])

    def get_key_schedule(self, key):
        keys = [key]
        for i in range(10):
            keys.append(self.key_schedule(keys[len(keys) - 1], i))
        return keys

    def mix_columns(self, data):
        for i in range(4):
            data[:, i] = self.mix_column(data[:, i])

    def encrypt(self):
        keys = self.get_key_schedule(self.key)
        self.data = self.add_round_key(self.data, self.key)
        for i in range(9):
            self.sub_bytes(self.data)
            self.data = self.rotate(self.data)
            self.mix_columns(self.data)
            self.data = self.add_round_key(self.data, keys[i + 1])
            print("phase {}:\n\n".format(i), self.data, '\n------------------------------------------------\n')
        self.sub_bytes(self.data)
        self.data = self.rotate(self.data)
        self.data = self.add_round_key(self.data, keys[10])

        print("last phase: \n\n", self.data)
        print('\n')
        return self.data


def main():
    data = np.array(
        [['0x32', '0x88', '0x31', '0xe0'], ['0x43', '0x5a', '0x31', '0x37'], ['0xf6', '0x30', '0x98', '0x07'],
         ['0xa8', '0x8d', '0xa2', '0x34']])
    key = np.array([['0x2b', '0x28', '0xab', '0x09'], ['0x7e', '0xae', '0xf7', '0xcf'],
                    ['0x15', '0xd2', '0x15', '0x4f'], ['0x16', '0xa6', '0x88', '0x3c']])

    print("original data: \n")
    print(data)
    print('\nkey:\n')
    print(key)
    print('\n')

    encipher = EncryptAES(data, key)
    encrypted = encipher.encrypt()

    print("encrypted: \n")
    print(encrypted)


if __name__ == '__main__':
    main()
