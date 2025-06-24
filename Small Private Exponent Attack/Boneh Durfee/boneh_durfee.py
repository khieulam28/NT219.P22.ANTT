import logging

from sage.all import RR
from sage.all import ZZ
from sage.all import Integer

import known_phi
import herrmann_may


def attack(N, e, factor_bit_length, delta=0.25, m=1, t=None):
    A = N + 1
    x, y = ZZ["x", "y"].gens()
    f = x * (A + y) + 1
    X = Integer(RR(e) ** delta)
    Y = Integer(2 ** int(factor_bit_length + 1))
    t = int((1 - 2 * delta) * m) if t is None else t
    logging.info(f"Trying m = {m}, t = {t}...")
    for x0, y0 in herrmann_may.modular_bivariate(f, e, m, t, X, Y):
        z = int(f(x0, y0))
        if z % e == 0:
            k = pow(x0, -1, e)
            s = (N + 1 + k) % e
            phi = N - s + 1
            factors = known_phi.factorize(N, phi)
            if factors:
                return factors

    return None, None
