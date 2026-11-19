import os, sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from curve import P256, INF, add, mul, mul_raw, is_on_curve, validate_point, InvalidPoint
import vss
from vss import (check_params, split_secret, reconstruct_secret, generate_feldman_commitments,
                 verify_share, random_coefficient, ReplayGuard)


@pytest.mark.parametrize("t,n", [(3, 5), (5, 9), (11, 21), (21, 41), (51, 101)])
def test_couples_valides(t, n):
    assert check_params(t, n)["(n-1) mod (k-1)"] == 0


@pytest.mark.parametrize("t,n", [(10, 20), (20, 50), (4, 8), (3, 6), (2, 1), (1, 5), (0, 5)])
def test_couples_rejetes(t, n):
    with pytest.raises(ValueError):
        check_params(t, n)
    with pytest.raises(ValueError):
        split_secret(5, t, n, P256.n)


def test_types_et_bornes():
    for bad in [(3.0, 5), (True, 5), (10**6, 10**6)]:
        with pytest.raises(ValueError):
            check_params(*bad)


def test_p256_cofacteur_1_et_ordre():
    assert P256.h == 1
    assert mul_raw(P256, P256.n, P256.G) is INF


def test_point_valide_accepte_et_ordre_complet():
    P = mul(P256, 123456789, P256.G)
    assert validate_point(P256, P) == P
    assert validate_point(P256, P, full_order_check=True) == P


def test_points_invalides_rejetes():
    x, y = P256.G
    # infini, hors courbe, coordonnées hors de [0, p), mauvais types
    for bad in [INF, (x, y + 1), (x + P256.p, y), (-1, y), (1.5, 2), (x,), "x", None, (True, 1)]:
        with pytest.raises(InvalidPoint):
            validate_point(P256, bad)


def test_attaque_courbe_invalide():
    # point d'une AUTRE courbe y^2 = x^3 - 3x + b' (mêmes p et a) : refusé par le test d'appartenance
    x, y = 5, 7
    b2 = (y * y - x ** 3 + 3 * x) % P256.p
    assert b2 != P256.b
    with pytest.raises(InvalidPoint):
        validate_point(P256, (x, y))


def test_engagement_malveillant_refuse_par_verify():
    coeffs, shares = split_secret(777, 3, 5, P256.n)
    comms = generate_feldman_commitments(coeffs, P256, P256.G)
    assert all(verify_share(s, comms, P256, P256.G, 5) for s in shares)
    bad = list(comms)
    bad[1] = (5, 7)                                   # point hors courbe
    assert not verify_share(shares[0], bad, P256, P256.G, 5)
    bad[1] = INF
    assert not verify_share(shares[0], bad, P256, P256.G, 5)


def test_parts_invalides_refusees():
    coeffs, shares = split_secret(777, 3, 5, P256.n)
    comms = generate_feldman_commitments(coeffs, P256, P256.G)
    x, y = shares[1]
    assert not verify_share((x, (y + 1) % P256.n), comms, P256, P256.G, 5)   # part modifiée
    assert not verify_share((0, y), comms, P256, P256.G, 5)                  # indice 0
    assert not verify_share((6, y), comms, P256, P256.G, 5)                  # indice > n
    assert not verify_share((x, P256.n), comms, P256, P256.G, 5)             # part hors de [0, q)


def test_reconstruction_ok():
    coeffs, shares = split_secret(424242, 3, 5, P256.n)
    assert reconstruct_secret([shares[0], shares[2], shares[4]], P256.n) == 424242


def test_rustsec_2024_0398_zero_possible_et_uniforme():
    # petit module : le coefficient 0 doit sortir, et toutes les valeurs doivent apparaître
    q = 7
    seen = {random_coefficient(q) for _ in range(2000)}
    assert seen == set(range(q))
    # borne basse : les coefficients de split_secret sont dans [0, q-1]
    coeffs, _ = split_secret(1, 3, 5, P256.n)
    assert all(0 <= c < P256.n for c in coeffs)


def test_anti_rejeu():
    g = ReplayGuard()
    n1 = g.new_nonce()
    assert g.accept("sessionA", 2, n1)
    assert not g.accept("sessionA", 2, n1)            # même soumission rejouée
    assert g.accept("sessionB", 2, n1)                # autre session : jeton distinct
    assert g.accept("sessionA", 2, g.new_nonce())
