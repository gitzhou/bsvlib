from bsvlib.curve import modular_inverse, multiply, curve, Point, get_y


def test_modular_inverse():
    assert modular_inverse(3, 7) == 5


def test_point_operation():
    k = 0xf97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a4b62
    p = multiply(k, curve.g)
    x = 0xe46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789
    y = 0x97693d32c540ac253de7a3dc73f7e4ba7b38d2dc1ecc8e07920b496fb107d6b2
    assert p == Point(x, y)
    assert y == get_y(x, y % 2 == 0)
