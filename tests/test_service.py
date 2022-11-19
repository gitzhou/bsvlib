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
