"""Vérifications exécutables par l'interface : chaque fonction renvoie {name, ok, detail}."""
import secrets

from curve import P256, INF, mul, mul_raw, validate_point, InvalidPoint
import vss


def _res(name, ok, detail):
    return {"name": name, "ok": bool(ok), "detail": detail}


def check_pairs():
    good = [(3, 5), (5, 9), (11, 21), (21, 41), (51, 101)]
    bad = [(10, 20), (20, 50), (4, 8), (3, 6)]
    ok_good = all(vss.check_params(k, n) for k, n in good)
    rejected = []
    for k, n in bad:
        try:
            vss.check_params(k, n)
        except ValueError:
            rejected.append((k, n))
    return _res("Contrainte (n-1) mod (k-1) = 0", ok_good and rejected == bad,
                f"acceptés {good} ; rejetés {rejected}")


def check_curve():
    ok = P256.h == 1 and mul_raw(P256, P256.n, P256.G) is INF
    return _res("P-256 : cofacteur 1 et n·G = infini", ok, f"h = {P256.h}")


def check_invalid_points():
    x, y = P256.G
    b2 = (5 * 0 + 7 * 7 - 5 ** 3 + 3 * 5) % P256.p            # point d'une autre courbe (courbe invalide)
    cases = {"infini": INF, "hors courbe": (x, y + 1), "autre courbe": (5, 7), "coordonnée >= p": (x + P256.p, y)}
    out = {}
    for name, pt in cases.items():
        try:
            validate_point(P256, pt)
            out[name] = "ACCEPTÉ (anormal)"
        except InvalidPoint:
            out[name] = "rejeté"
    ok = all(v == "rejeté" for v in out.values()) and validate_point(P256, mul(P256, 12345, P256.G))
    return _res("Validation des points (sous-groupes, courbe invalide)", ok, out)


def check_rustsec():
    q = 7
    seen = {vss.random_coefficient(q) for _ in range(2000)}
    return _res("RUSTSEC-2024-0398 : coefficient 0 possible, distribution complète",
                seen == set(range(q)), f"valeurs vues sur Z_7 : {sorted(seen)}")


def check_replay():
    g = vss.ReplayGuard()
    n1 = g.new_nonce()
    first, again, other = g.accept("A", 2, n1), g.accept("A", 2, n1), g.accept("B", 2, n1)
    return _res("Anti-rejeu", first and not again and other,
                {"1re soumission": first, "rejouée": again, "autre session": other})


def check_roundtrip(k=3, n=5):
    secret = secrets.randbelow(P256.n)
    coeffs, shares = vss.split_secret(secret, k, n, P256.n)
    comms = vss.generate_feldman_commitments(coeffs, P256, P256.G)
    valid = all(vss.verify_share(s, comms, P256, P256.G, n) for s in shares)
    got = vss.reconstruct_secret([shares[0], shares[2], shares[4]], P256.n)
    x, y = shares[1]
    tampered = vss.verify_share((x, (y + 1) % P256.n), comms, P256, P256.G, n)
    few = vss.reconstruct_secret(shares[:k - 1], P256.n)
    ok = valid and got == secret and not tampered and few != secret
    return _res("Partage, Feldman, reconstruction (k, n) = (3, 5)", ok,
                {"toutes les parts valides": valid, "reconstruction avec 3 parts exacte": got == secret,
                 "part modifiée détectée": not tampered, "k-1 parts ne donnent pas le secret": few != secret})


def run_all():
    fns = [check_pairs, check_curve, check_invalid_points, check_rustsec, check_replay, check_roundtrip]
    return [f() for f in fns]
