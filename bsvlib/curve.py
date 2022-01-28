from collections import namedtuple
from typing import Optional

from coincurve import PublicKey as CcPublicKey

from .constants import NUMBER_BYTE_LENGTH

Point = namedtuple('Point', 'x y')

EllipticCurve = namedtuple('EllipticCurve', 'name p a b g n h')
curve = EllipticCurve(
    name='Secp256k1',
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    a=0,
    b=7,
    g=Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    h=1,
)


def on_curve(point: Optional[Point]) -> bool:
    """
    :returns: True if the given point lies on the elliptic curve
    """
    if point is None:
        # None represents the point at infinity.
        return True
    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def negative(point: Optional[Point]) -> Optional[Point]:
    """
    :returns: -point
    """
    assert on_curve(point)
    if point is None:
        # -0 = 0
        return None
    x, y = point
    r = Point(x, -y % curve.p)
    assert on_curve(r)
    return r


def add(p: Optional[Point], q: Optional[Point]) -> Optional[Point]:
    """
    :returns: the result of p + q according to the group law
    """
    assert on_curve(p)
    assert on_curve(q)
    if p is None:
        # 0 + q = q
        return q
    if q is None:
        # p + 0 = p
        return p
    if p == negative(q):
        # p == -q
        return None
    # p != -q
    r = Point(*CcPublicKey.from_point(*p).combine([CcPublicKey.from_point(*q)]).point())
    assert on_curve(r)
    return r


def multiply(scalar: int, point: Optional[Point]) -> Optional[Point]:
    """
    multiply the given point by a scalar
    """
    assert on_curve(point)
    if scalar % curve.n == 0 or point is None:
        return None
    if scalar < 0:
        # k * point = -k * (-point)
        return multiply(-scalar, negative(point))
    r = Point(*CcPublicKey.from_point(*point).multiply((scalar % curve.n).to_bytes(NUMBER_BYTE_LENGTH, 'big')).point())
    assert on_curve(r)
    return r


def get_y(x: int, even: bool) -> int:
    """
    point (x, y) lies on the curve, calculate y from the given x and the parity of y
    """
    y_square = (x * x * x + curve.a * x + curve.b) % curve.p
    y = pow(y_square, (curve.p + 1) // 4, curve.p)
    return y if (y + (0 if even else 1)) % 2 == 0 else -y % curve.p
