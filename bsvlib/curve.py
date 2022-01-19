from collections import namedtuple
from typing import Optional, Tuple

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


def extended_euclid_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    :returns: [gcd(a, b), x, y] where ax + by = gcd(a, b)
    """
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = b, a
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def modular_inverse(num: int, n: int) -> int:
    """
    require num and n are co-prime
    :returns: modular multiplicative inverse of num under n
    """
    # find gcd using Extended Euclid's Algorithm
    gcd, x, y = extended_euclid_gcd(num, n)
    # in case x is negative, we handle it by adding extra n
    # because we know that modular multiplicative inverse of num in range n lies in the range [0, n-1]
    if x < 0:
        x += n
    return x


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
    xp, yp = p
    xq, yq = q
    if p == q:
        m = (3 * xp * xp + curve.a) * modular_inverse(2 * yp, curve.p)
    else:
        m = (yp - yq) * modular_inverse(xp - xq, curve.p)
    x = m * m - xp - xq
    y = yp + m * (x - xp)
    r = Point(x % curve.p, -y % curve.p)
    assert on_curve(r)
    return r


def multiply(k: int, point: Optional[Point]) -> Optional[Point]:
    """
    :returns: k * point computed using the double and add algorithm
    """
    assert on_curve(point)
    if k % curve.n == 0 or point is None:
        return None
    if k < 0:
        # k * point = -k * (-point)
        return multiply(-k, negative(point))
    # double and add
    r = None
    while k:
        if k & 1:
            r = add(r, point)
        point = add(point, point)
        k >>= 1
    assert on_curve(r)
    return r


def get_y(x: int, even: bool) -> int:
    """
    calculate y from x and the parity of y
    """
    y_square = (x * x * x + curve.a * x + curve.b) % curve.p
    y = pow(y_square, (curve.p + 1) // 4, curve.p)
    return y if (y + (0 if even else 1)) % 2 == 0 else -y % curve.p
