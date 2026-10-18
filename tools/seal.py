#!/usr/bin/env python3
"""seal.py — scelle le site slabb.dev.

Chaque fichier est haché (SHA-256), les haches sont chaînées (même architecture
de journal chaîné que noirebox), et la tête de chaîne est signée Ed25519
(RFC 8032, implémentation stdlib auto-testée sur les vecteurs officiels).

Génère : manifest.json, seal-journal.jsonl, pubkey.b64
La clé privée vit dans keys/ — JAMAIS committée.
"""
import base64
import datetime
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
import os
FILES = ["client.html", "index.html", "replay.json", "tech.html", "verify.html", "verify.py"]
FILES += [f for f in os.environ.get("SEAL_EXTRA", "").split(",") if f]
FILES.sort()
GENESIS = "slabb.dev-genesis"

# --- Ed25519 (RFC 8032), affine, stdlib only -------------------------------
p = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
I = pow(2, (p - 1) // 4, p)
d = (-121665 * pow(121666, p - 2, p)) % p


def inv(x):
    return pow(x, p - 2, p)


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1) % p
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if (x * x - xx) % p != 0:
        raise ValueError("point non récupérable")
    if x % 2 != 0:
        x = p - x
    return x


By = 4 * inv(5) % p
B = (xrecover(By), By)


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


def encodepoint(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


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


def clamp(h):
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, "little")


def publickey(sk):
    h = hashlib.sha512(sk).digest()
    return encodepoint(scalarmult(B, clamp(h)))


def signature(sk, msg):
    h = hashlib.sha512(sk).digest()
    a = clamp(h)
    prefix = h[32:]
    A = encodepoint(scalarmult(B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % l
    R = encodepoint(scalarmult(B, r))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % l
    S = (r + k * a) % l
    return R + S.to_bytes(32, "little")


def verify(pk, msg, sig):
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


# vecteurs RFC 8032 TEST 1 — si ça rate, on ne scelle rien
_SK = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
_PK = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
_SG = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
assert publickey(_SK) == _PK, "self-test ed25519 publickey KO"
assert signature(_SK, b"") == _SG, "self-test ed25519 signature KO"
assert verify(_PK, b"", _SG), "self-test ed25519 verify KO"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def to_pem(raw):
    spki = bytes.fromhex("302a300506032b6570032100") + raw
    b64 = base64.b64encode(spki).decode()
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def main():
    entries = []
    for name in FILES:
        f = ROOT / name
        if not f.exists():
            sys.exit(f"manquant : {name}")
        data = f.read_bytes()
        entries.append({"name": name, "sha256": sha(data), "bytes": len(data)})

    head = sha(GENESIS.encode())
    for e in entries:
        head = sha((head + e["name"] + e["sha256"]).encode())

    keys = pathlib.Path(os.environ.get("SLABB_KEYS") or (ROOT / "keys"))
    keys.mkdir(exist_ok=True)
    sk_file = keys / "seal.key"
    if not sk_file.exists():
        sk_file.write_bytes(hashlib.sha512(os.urandom(32)).digest()[:32])
        os.chmod(sk_file, 0o600)
        print("clé Ed25519 générée → keys/seal.key (chmod 600 — JAMAIS committée)")
    sk = sk_file.read_bytes()
    pk = publickey(sk)

    sig = signature(sk, head.encode())
    assert verify(pk, head.encode(), sig), "auto-vérification du sceau KO"

    pub_b64 = base64.b64encode(pk).decode()
    (ROOT / "pubkey.b64").write_text(pub_b64 + "\n")

    manifest = {
        "site": "slabb.dev",
        "format": "seal v1 — SHA-256 chaînés + Ed25519 (architecture journal noirebox)",
        "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "genesis": GENESIS,
        "files": entries,
        "head": head,
        "sig": base64.b64encode(sig).decode(),
        "pubkey": pub_b64,
        "fingerprint": "sha256:" + sha(pk)[:16],
    }
    (ROOT / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    )

    lines = []
    prev = GENESIS
    for n, e in enumerate(entries, 1):
        lines.append(
            json.dumps(
                {"n": n, "event": "file", "name": e["name"], "sha256": e["sha256"], "prev": prev}
            )
        )
        prev = e["sha256"]
    lines.append(
        json.dumps({"n": len(entries) + 1, "event": "seal", "head": head, "prev": prev})
    )
    (ROOT / "seal-journal.jsonl").write_text("\n".join(lines) + "\n")

    print(f"scellé — head {head[:16]}…  fingerprint {manifest['fingerprint']}  ({len(entries)} fichiers)")


if __name__ == "__main__":
    main()
