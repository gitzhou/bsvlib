import random

from bsvlib.constants import OP
from bsvlib.script import Script
from bsvlib.utils import encode_int
from helper import create_then_spend

a = random.randint(-128, 128)
b = random.randint(-128, 128)
print(a, b)

# locking script requires the result of a + b
locking = Script(encode_int(a) + encode_int(b) + OP.OP_ADD + OP.OP_EQUAL)
# unlocking script provides the result
unlocking = Script(encode_int(a + b))

create_then_spend(locking, unlocking)
