import secrets
from curve import P256, mul, add, INF, validate_point

def eval_poly(coeffs, x, prime):
    """Évalue un polynôme de coefficients donnés en un point x modulo prime."""
    res = 0
    for coeff in reversed(coeffs):
        res = (res * x + coeff) % prime
    return res

MAX_T, MAX_N = 256, 1024


def check_params(t, n_participants):
    """
    Règle de l'encadrante : (n - 1) mod (k - 1) = 0, avec k = seuil (t ici) et n = nombre de
    participants. Tout couple qui ne la respecte pas est REJETÉ (aucun mode permissif).
    Couples valides : n = m*(k - 1) + 1, par ex. (3,5), (5,9), (11,21). Rejetés : (10,20), (4,8).
    """
    for name, v in (("t", t), ("n", n_participants)):
        if type(v) is not int:
            raise ValueError(f"{name} doit être un entier")
    if not (2 <= t <= n_participants):
        raise ValueError("il faut 2 <= t <= n")
    if t > MAX_T or n_participants > MAX_N:
        raise ValueError(f"bornes dépassées (t <= {MAX_T}, n <= {MAX_N})")
    if (n_participants - 1) % (t - 1) != 0:
        raise ValueError(
            f"Paramètres invalides : (n - 1) mod (k - 1) = {(n_participants - 1) % (t - 1)} != 0 "
            f"pour k = {t}, n = {n_participants}.")
    return {"k": t, "n": n_participants, "(n-1) mod (k-1)": 0}


def random_coefficient(prime):
    """
    Coefficient uniforme dans [0, prime - 1], zéro INCLUS (secrets.randbelow).
    RUSTSEC-2024-0398 (crate Rust `sharks`) : les coefficients étaient tirés dans [1, 255] au lieu
    de [0, 255] ; en repartageant un même secret, un attaquant écarte des valeurs possibles.
    Ici la borne basse est 0, donc la distribution est uniforme sur tout Z_prime.
    """
    return secrets.randbelow(prime)


def split_secret(secret, t, n_participants, prime):
    """
    Divise un secret en n_participants parts avec un seuil t.
    - secret : l'entier à cacher (ex: une clé privée), dans [0, prime - 1]
    - t : le seuil minimal de parts requises pour reconstruire
    - n_participants : le nombre total de parts créées
    - prime : l'ordre du corps de partage (ex: P256.n)
    """
    check_params(t, n_participants)
    if type(secret) is not int or not (0 <= secret < prime):
        raise ValueError("secret hors de [0, prime - 1]")

    # 1. Coefficients (a_0 = secret), a_1..a_{t-1} uniformes sur [0, prime - 1]
    coeffs = [secret] + [random_coefficient(prime) for _ in range(t - 1)]

    # 2. Parts (x, f(x)) pour x = 1..n
    shares = [(i, eval_poly(coeffs, i, prime)) for i in range(1, n_participants + 1)]
    return coeffs, shares

def lagrange_interpolate(x, points, prime):
    """
    Interpole le polynôme de Lagrange en un point x (généralement x=0 pour le secret)
    à partir d'un sous-ensemble de points (parts).
    """
    k = len(points)
    x_s = [p[0] for p in points]
    y_s = [p[1] for p in points]
    
    acc = 0
    for i in range(k):
        numerator, denominator = 1, 1
        for j in range(k):
            if i != j:
                numerator = (numerator * (x - x_s[j])) % prime
                denominator = (denominator * (x_s[i] - x_s[j])) % prime
        
        # Calcul du polynôme de base de Lagrange L_i(x) modulo prime
        lagrange_basis = (numerator * pow(denominator, -1, prime)) % prime
        term = (y_s[i] * lagrange_basis) % prime
        acc = (acc + term) % prime
        
    return acc

def reconstruct_secret(shares, prime):
    """Reconstruit le secret original f(0) à partir de t parts valides."""
    return lagrange_interpolate(0, shares, prime)

def generate_feldman_commitments(coeffs, C, G):
    """Engagements publics de Feldman : C_j = a_j * G pour chaque coefficient."""
    validate_point(C, G)
    return [mul(C, coeff, G) for coeff in coeffs]


def verify_share(share, commitments, C, G, n_participants=None):
    """
    Vérifie qu'une part (x, y) est valide par rapport aux engagements publics de Feldman.
    Vérification : y * G == Somme( x^j * C_j )
    Les entrées sont validées d'abord : engagements sur la courbe (non infinis, cofacteur 1),
    indice et part dans leurs bornes. Toute entrée invalide renvoie False (jamais d'exception
    dépendant du secret).
    """
    try:
        x, y = share
        if type(x) is not int or type(y) is not int:
            return False
        if not (1 <= x and (n_participants is None or x <= n_participants)):
            return False
        if not (0 <= y < C.n):
            return False
        for c in commitments:
            validate_point(C, c)
        validate_point(C, G)
    except ValueError:
        return False

    left_side = mul(C, y, G)
    right_side = INF
    x_pow = 1
    for commitment in commitments:
        right_side = add(C, right_side, mul(C, x_pow, commitment))
        x_pow = (x_pow * x) % C.n
    return left_side == right_side


class ReplayGuard:
    """
    Anti-rejeu : chaque soumission (session, indice, nonce) n'est acceptée qu'une fois.
    Une part ou une demande déjà vue (copiée dans un échange passé) est refusée ; le nonce lie la
    soumission à une session précise, donc une soumission valide dans la session A est rejetée en B.
    """

    def __init__(self):
        self._seen = set()

    def new_nonce(self):
        return secrets.token_hex(16)

    def accept(self, session_id, index, nonce):
        key = (session_id, index, nonce)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True
