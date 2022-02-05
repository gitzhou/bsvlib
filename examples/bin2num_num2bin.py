import time

from bsvlib.constants import OP
from bsvlib.script import Script
from bsvlib.utils import encode_pushdata, encode_int
from helper import create_then_spend


def bin2num():
    # bytes "00 00 00 80 00 00 80" will be converted to integer -2147483648
    locking = Script(encode_pushdata(bytes.fromhex('00 00 00 80 00 00 80')) + OP.OP_BIN2NUM + OP.OP_EQUAL)
    unlocking = Script(encode_int(-2147483648))
    create_then_spend(locking, unlocking)


def num2bin():
    # integer 2147483648 will be converted to 5 bytes "00 00 00 80 00" (minimal encoding)
    # here we convert to 10 bytes, that would be "00 00 00 80 00 00 00 00 00 00"
    locking = Script(encode_int(2147483648) + encode_int(10) + OP.OP_NUM2BIN + OP.OP_EQUAL)
    unlocking = Script(encode_pushdata(bytes.fromhex('00 00 00 80 00 00 00 00 00 00')))
    create_then_spend(locking, unlocking)


if __name__ == '__main__':
    print('bin2num')
    bin2num()
    time.sleep(2)
    print('num2bin')
    num2bin()
