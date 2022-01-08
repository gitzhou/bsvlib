from bsvlib.hash import sha256, double_sha256, ripemd160_sha256

MESSAGE_BYTES = 'hello'.encode('utf-8')


def test_sha256():
    assert sha256(MESSAGE_BYTES) == bytes.fromhex('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')


def test_double_sha256():
    assert double_sha256(MESSAGE_BYTES) == bytes.fromhex('9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50')


def test_ripemd160_sha256():
    assert ripemd160_sha256(MESSAGE_BYTES) == bytes.fromhex('b6a9c8c230722b7c748331a8b450f05566dc7d0f')
