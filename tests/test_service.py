from bsvlib.constants import METASV_TOKEN, Chain
from bsvlib.service.metasv import MetaSV
from bsvlib.service.service import Service
from bsvlib.service.whatsonchain import WhatsOnChain


def test_service():
    if METASV_TOKEN:
        assert isinstance(Service().provider, MetaSV)
    else:
        assert isinstance(Service().provider, WhatsOnChain)

    assert isinstance(Service(chain=Chain.TEST).provider, WhatsOnChain)


def test_metasv():
    if METASV_TOKEN:
        service = MetaSV(token=METASV_TOKEN)
        address = '13LGR1QjYkdi4adZV1Go6cQTxFYjquhS1y'
        unspents = service.get_unspents(address=address)
        balance = service.get_balance(address=address)
        assert sum([unspent['satoshi'] for unspent in unspents]) == balance
