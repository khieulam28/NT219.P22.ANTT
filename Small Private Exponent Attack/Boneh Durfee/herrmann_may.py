import logging

from sage.all import ZZ

import small_roots


def modular_bivariate(f, e, m, t, X, Y, roots_method="groebner"):
    f = f.change_ring(ZZ)

    pr = ZZ["x", "y", "u"]
    x, y, u = pr.gens()
    qr = pr.quotient(1 + x * y - u)
    U = X * Y

    logging.debug("Generating shifts...")

    shifts = []
    for k in range(m + 1):
        for i in range(m - k + 1):
            g = x ** i * f ** k * e ** (m - k)
            g = qr(g).lift()
            shifts.append(g)

    for j in range(1, t + 1):
        for k in range(m // t * j, m + 1):
            h = y ** j * f ** k * e ** (m - k)
            h = qr(h).lift()
            shifts.append(h)

    L, monomials = small_roots.create_lattice(pr, shifts, [X, Y, U])
    L = small_roots.reduce_lattice(L)

    pr = f.parent()
    x, y = pr.gens()

    polynomials = small_roots.reconstruct_polynomials(L, f, None, monomials, [X, Y, U], preprocess_polynomial=lambda p: p(x, y, 1 + x * y))
    for roots in small_roots.find_roots(pr, polynomials, method=roots_method):
        yield roots[x], roots[y]
