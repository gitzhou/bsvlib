from typing import Optional

import requests

from bsvlib import Transaction, Key, Unspent
from bsvlib.service import MetaSV

MIN_CONSOLIDATION_INPUTS = 100
MERGE_COUNT = 3000

WIF = ''  # Your WIF
LEFTOVER = ''  # if None or empty, then merge into the address corresponding to WIF


def get_block_height() -> int:
    return requests.get('https://apiv2.metasv.com/block/info').json()['blocks']


def pick_confirmed(wif):
    unspents = Unspent.get_unspents(provider=MetaSV(), private_keys=[Key(wif)])
    print(f'total {len(unspents)}')
    current_height = get_block_height()
    picked = []
    for unspent in unspents:
        if unspent.height != -1 and current_height - unspent.height >= 6:
            picked.append(unspent)
    print(f'picked {len(picked)}')
    return picked


def merge(wif: str, leftover: Optional[str] = None):
    picked_unspents = pick_confirmed(wif)
    unspents_groups = [picked_unspents[i:i + MERGE_COUNT] for i in range(0, len(picked_unspents), MERGE_COUNT)]
    print(f'send {len(unspents_groups)} transactions')
    for unspents_group in unspents_groups:
        if len(unspents_group) > MIN_CONSOLIDATION_INPUTS:
            print(Transaction(fee_rate=0).add_inputs(unspents_group).add_change(leftover).sign().broadcast())
        else:
            print(f'skip, only {len(unspents_group)} unspents')


if __name__ == '__main__':
    merge(WIF, LEFTOVER)
