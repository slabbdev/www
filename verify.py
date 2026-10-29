#!/usr/bin/env python3
"""verify.py, vérification hors-bande d'un déploiement slabb.dev.

    python3 verify.py                      # contre https://slabb.dev
    python3 verify.py https://autre-host   # contre un miroir
    python3 verify.py .                    # contre un clone local

Refait tout ce que verify.html fait, sans navigateur : hash SHA-256 de chaque
fichier, recomputation de la chaîne, vérification de la signature Ed25519.
Ce que ça prouve : le contenu n'a pas bougé depuis la construction signée.
Ce que ça ne prouve pas : que le contenu est vrai, voir le pin out-of-band
(fingerprint de la clé à comparer avec une copie publiée ailleurs).
"""
import base64
import hashlib
import json
import pathlib
import sys
import urllib.request

p = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
I = pow(2, (p - 1) // 4, p)
d = (-121665 * pow(121666, p - 2, p)) % p
By = 4 * pow(5, p - 2, p) % p
Bx = None  # rempli après inv()


def inv(x):
    return pow(x, p - 2, p)


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1) % p
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if (x * x - xx) % p != 0:
        raise ValueError("point non carré")
    if x % 2 != 0:
        x = p - x
    return x


Bx = xrecover(By)
B = (Bx, By)


def edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2)
    return (x3 % p, y3 % p)


def scalarmult(P, e):
    if e == 0:
        return (0, 1)
    Q = scalarmult(P, e // 2)
    Q = edwards(Q, Q)
    if e & 1:
        Q = edwards(Q, P)
    return Q


def decodepoint(b):
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= p:
        raise ValueError("y hors corps")
    xx = (y * y - 1) * inv(d * y * y + 1) % p
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if (x * x - xx) % p != 0:
        raise ValueError("point non carré")
    if x % 2 != sign:
        x = p - x
    return (x, y)


def verify(pk, msg, sig):
    if len(pk) != 32 or len(sig) != 64:
        return False
    R = sig[:32]
    S = int.from_bytes(sig[32:], "little")
    if S >= l:
        return False
    try:
        A = decodepoint(pk)
        Rr = decodepoint(R)
    except ValueError:
        return False
    k = int.from_bytes(hashlib.sha512(R + pk + msg).digest(), "little") % l
    return scalarmult(B, S) == edwards(Rr, scalarmult(A, k))


# vecteur RFC 8032 TEST 1
assert verify(
    bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    b"",
    bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ),
), "self-test ed25519 KO"


def main():
    import os
    FR = (os.environ.get("LANG", "fr") or "fr").lower().startswith("fr")
    def T(fr, en):
        return fr if FR else en
    base = sys.argv[1] if len(sys.argv) > 1 else "https://slabb.dev"
    base = base.rstrip("/")

    def fetch(path):
        if base.startswith("http"):
            with urllib.request.urlopen(f"{base}/{path}", timeout=15) as r:
                return r.read()
        return (pathlib.Path(base) / path).read_bytes()

    try:
        man = json.loads(fetch("manifest.json"))
    except Exception as e:
        sys.exit(T(f"manifest.json illisible : {e}", f"manifest.json unreadable: {e}"))

    ok = True
    print(f"site        {man.get('site')}  (format : {man.get('format')})")
    print(T("construit   ", "built       ") + str(man.get("built_at")))
    print("")
    print(T("fichiers", "files"))
    for f in man["files"]:
        h = hashlib.sha256(fetch(f["name"])).hexdigest()
        good = h == f["sha256"]
        ok = ok and good
        print(f"  {'PASS' if good else 'FAIL'}  {f['name']:<14} {h[:16]}…")
        if not good:
            print(T("        attendu ", "        expected ") + f["sha256"])

    head = hashlib.sha256(b"slabb.dev-genesis").hexdigest()
    for f in man["files"]:
        head = hashlib.sha256((head + f["name"] + f["sha256"]).encode()).hexdigest()
    chain_ok = head == man["head"]
    ok = ok and chain_ok
    print("")
    print(T("chaîne      ", "chain       ") + ("PASS" if chain_ok else "FAIL") + f"  head {head[:16]}…")

    try:
        pk = base64.b64decode(man["pubkey"])
        sig = base64.b64decode(man["sig"])
        sig_ok = verify(pk, man["head"].encode(), sig)
    except Exception:
        sig_ok = False
    ok = ok and sig_ok
    print(("signature   ") + ("PASS" if sig_ok else "FAIL") + T("  Ed25519 sur la tête de chaîne", "  Ed25519 over the chain head"))
    print(f"fingerprint {man.get('fingerprint')}  " + T("← comparez-le à une copie hors-bande (release GitHub, post dev.to)", "← compare it with an out-of-band copy (GitHub release, dev.to post)"))
    print("")
    print(T("VERDICT : ", "VERDICT: ") + (T("INTÈGRE, rien n'a bougé depuis la construction signée.", "INTACT, nothing has changed since the signed build.") if ok else T("COMPROMIS ou corrompu, ne faites pas confiance à ce déploiement.", "COMPROMISED or corrupted, do not trust this deployment.")))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
