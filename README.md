# Vss_ECC : partage de secret vérifiable (Shamir + Feldman) sur P-256

Projet de Master Cryptographie et Sécurité de l'Information (Université Mohammed V, Rabat), encadré par Dr Zineb Bakraouy.

Le projet partage un secret (par exemple une clé privée) entre **n** participants. **k** d'entre eux (le seuil) suffisent à le reconstruire, moins de k n'apprennent rien, et chaque participant peut **vérifier sa part** sans connaître le secret. Les engagements publics reposent sur la courbe elliptique **P-256** (secp256r1).

> Code pédagogique : non audité, non constant en temps, à ne pas utiliser en production.

## Ce que fait le code

| Fonction | Où | Rôle |
| --- | --- | --- |
| Courbe P-256 | `curve.py` | Addition, multiplication scalaire, validation de points |
| Partage de Shamir | `vss.py` | Polynôme de degré k−1 sur Z_q, évaluation de Horner, reconstruction par interpolation de Lagrange |
| Engagements de Feldman | `vss.py` | C_j = a_j·G ; vérification s_i·G = Σ i^j·C_j |
| Contrôle des paramètres | `check_params` | Rejette tout couple (k, n) tel que (n−1) mod (k−1) ≠ 0 |
| Anti-rejeu | `ReplayGuard` | Une soumission (session, indice, nonce) n'est acceptée qu'une fois |
| Démonstration | `main.py` | Partage, vérification de chaque part, reconstruction du secret |

## Notations

- k = seuil (noté `t` dans le code), n = nombre de participants, q = ordre du générateur G de P-256, h = 1 = cofacteur.
- Couples valides : n = m·(k−1) + 1, par exemple (3,5), (5,9), (11,21), (21,41), (51,101).
  Couples rejetés : (10,20), (20,50), (4,8).

## Sécurité

- **Paramètres** : `check_params` applique strictement (n−1) mod (k−1) = 0, avec contrôle des types et des bornes (2 ≤ k ≤ n, k ≤ 256, n ≤ 1024). Il n'y a pas de mode permissif.
- **Validation de la courbe** : tout point reçu est refusé s'il est hors de [0, p)², égal à l'infini ou hors de la courbe y² = x³ − 3x + b. P-256 a un cofacteur 1 : tout point valide (sauf l'infini) est d'ordre q, donc il n'y a pas de petit sous-groupe à exploiter. Ce contrôle suffit contre l'attaque par courbe invalide. `validate_point(..., full_order_check=True)` ajoute le test q·P = O et devient obligatoire pour une courbe de cofacteur supérieur à 1.
- **RUSTSEC-2024-0398** : cet avis concerne la crate Rust `sharks`, dont les coefficients du polynôme étaient tirés dans [1, 255] au lieu de [0, 255], ce qui permet d'exclure des valeurs quand on repartage un même secret. Ici, `random_coefficient` utilise `secrets.randbelow(q)`, uniforme sur [0, q−1], zéro inclus. Un test le vérifie.
- **Entrées** : `verify_share` renvoie `False` pour une part, un indice ou un engagement invalide, sans exception qui dépendrait du secret.
- **Anti-rejeu** : `ReplayGuard` refuse de rejouer une soumission et lie chaque jeton à une session.

## Installation et lancement

Prérequis : Python 3.10 ou plus.

```bash
# Linux / macOS
./setup.sh

# Windows (PowerShell)
.\setup.ps1
```

Les scripts créent `.venv`, installent `requirements.txt`, lancent les tests et ouvrent VS Code s'il est installé. À la main :

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python3 -m pytest -q tests       # 22 tests
python3 main.py                  # démonstration de bout en bout
python3 check.py                 # partage et reconstruction d'un petit secret
```

Sur Windows, si PowerShell refuse le script : `Set-ExecutionPolicy -Scope Process Bypass`.

## Structure

```
curve.py               P-256, addition, multiplication, validate_point
vss.py                 Shamir, Lagrange, Feldman, check_params, ReplayGuard
main.py                démonstration de bout en bout
check.py               vérification rapide du partage et de la reconstruction
tests/test_security.py 22 tests (paramètres, points invalides, Feldman, RUSTSEC, rejeu)
requirements.txt       cryptography, pytest
setup.sh, setup.ps1    création de l'environnement
.vscode/               réglages pytest, lancement et extensions recommandées
```

## Exemple

```python
from curve import P256
from vss import split_secret, generate_feldman_commitments, verify_share, reconstruct_secret

k, n = 3, 5                                         # (5-1) mod (3-1) = 0 : valide
coeffs, shares = split_secret(424242, k, n, P256.n)
commitments = generate_feldman_commitments(coeffs, P256, P256.G)

assert all(verify_share(s, commitments, P256, P256.G, n) for s in shares)
assert reconstruct_secret([shares[0], shares[2], shares[4]], P256.n) == 424242
```

## Limites

- Les engagements de Feldman cachent le secret seulement computationnellement (Q = d·G est public).
- L'arithmétique modulaire est en entiers Python, donc non constante en temps.
- Le dealer connaît le secret par construction.
- Ce dépôt contient la partie cryptographique. Les modules suivants sont prévus, pas encore ici : engagements de Pedersen, signature ECDSA, registre public (blockchain), interface.

## Feuille de route

1. Engagements de Pedersen (confidentialité parfaite) et benchmark Feldman contre Pedersen.
2. Authentification par signature ECDSA avec le secret reconstruit.
3. Registre public : engagements publiés, preuve de fraude, disqualification du dealer.
4. Interface pour le dealer et les participants.

## Références

- A. Shamir, « How to Share a Secret », 1979.
- P. Feldman, « A Practical Scheme for Non-interactive Verifiable Secret Sharing », 1987.
- T. Pedersen, « Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing », 1991.
- RFC 6979 (ECDSA déterministe) ; FIPS 186-5 (paramètres de P-256).
- RUSTSEC-2024-0398 : biais des coefficients dans la crate `sharks`.
