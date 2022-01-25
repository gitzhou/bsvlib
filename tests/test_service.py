from bsvlib.constants import METASV_TOKEN
from bsvlib.service.metasv import MetaSV


def test_metasv():
    if METASV_TOKEN:
        service = MetaSV(METASV_TOKEN)
        address = '13LGR1QjYkdi4adZV1Go6cQTxFYjquhS1y'
        unspents = service.get_unspents(address=address)
        balance = service.get_balance(address=address)
        assert sum([unspent['satoshi'] for unspent in unspents]) == balance
