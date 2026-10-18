# slabb.dev — le site scellé + l'agent qui le fait vivre

Zéro dépendance front, zéro build, zéro tracking. Tout est HTML/CSS/JS inline.
Et le site est **scellé** : chaque fichier est haché, les haches chaînées, la tête signée Ed25519 — voir « Scellement » plus bas.

## La démo agent (intégrée)

`agent.html` — le visiteur donne une mission, un agent **GLM-4.5-flash (free, via z.ai)** réfléchit,
pilote **navette** (le vrai binaire Rust, autospawn) pour lire une vraie page, scelle sa conclusion
dans `journal.jsonl` (chaîné, tête signée Ed25519 après chaque run). Tout est affiché, hash compris.

    npm install
    npm start          # http://127.0.0.1:8791 — sert le site entier + /api/* + autospawn navette

- Clé modèle : `~/.zcode/secrets/zai.key`. Sans clé → **mode démo scripté** (affiché honnêtement).
- Navette : `../navette/target/release/navette` (ou `NAVETTE_BIN=…`), port 8890.
- Privé et **jamais servi** (403) : `keys/` (clé Ed25519), `agent/` (code serveur), `node_modules/`.
- Sur un hébergement statique pur (Pages), tout le site marche sauf la démo — qui affiche
  d'elle-même le bandeau « serveur éteint » et la commande pour le lancer.

## Structure
- `index.html` — **splash / porte d'entrée** : « Vous êtes plutôt… je suis tech / pas du tout du tout du tout ». Deux portes, curseur clignotant, boot log du sceau, pluie de hex, touches 1/2.
- `tech.html` — **LA page unique** : 6 métiers (dev, agents IA, CI/CD & plateforme, sécurité & audit, conformité par la preuve, transmission), laboratoire de preuve (chaîne SHA-256 altérable + matrice des 200 URLs réelles), **démo agent en direct (chat + journal chaîné)**, 6 produits, écrits, contact, toggle FR/EN.
- `client.html` — **version « pas du tout » (non-tech)** : zéro jargon, 4 services orientés problème, produits traduits en clair, toggle FR/EN.
- `verify.html` — **la page de vérification** : bouton qui re-hash tout en WebCrypto (SHA-256), recompose la chaîne, vérifie la signature Ed25519. Plus le pin out-of-band affiché en clair.
- `verify.py` — **vérification hors-bande** (`python3 verify.py https://slabb.dev`), stdlib, auto-testée sur les vecteurs RFC 8032.
- `manifest.json` + `journal.jsonl` + `pubkey.b64` — le sceau public (générés par `tools/seal.py`).
- `tools/seal.py` — le seleur.
- `tech.html` embarque aussi le **laboratoire de preuve** : chaîne SHA-256 altérable en direct (WebCrypto) + la matrice des 200 URLs réelles du bench tollbooth (données embarquées depuis `navette/bench/tollbooth-results.json`, CC BY 4.0 — 165 lisibles / 23 JS-gate / 12 challenges / 73 sites bannissant les bots IA / 1 paywall / 0 x402). `keys/seal.key` (0600) = clé privée, JAMAIS committée (voir `.gitignore`).

## Scellement (à refaire avant CHAQUE déploiement)

    python3 tools/seal.py      # re-hash + chaîne + signature + manifest + journal
    python3 verify.py .        # auto-contrôle — doit finir sur « INTÈGRE »

Head actuel : cf. manifest.json (change à chaque seal) · fingerprint de la clé : `sha256:5d7e19291be7eb6b`
⚠️ **Le fingerprint de la clé doit être publié hors-bande** (release GitHub du repo du site, post dev.to) — c'est lui qui détecte un remplacement total du site. Le signer à la main dans un post à la première mise en ligne.

## Mettre en ligne — GitHub Pages (le mode actuel)

    ./deploy/pages.sh            # construit dist-pages/ : statique + journal en instantané, scellé, vérifié

Puis pousser **le contenu de `dist-pages/`** sur le repo `slabbdev/slabbdev.github.io` (branche `main`),
activer Pages (Settings → Pages → Deploy from branch), et quand le DNS est prêt : `CNAME=slabb.dev ./deploy/pages.sh`
+ enregistrements A → 185.199.108/109/110/111.153 + « Enforce HTTPS ».

**Ce qui tourne sur Pages** : tout — splash, page unique, hachoir live, labo, matrice, registre, **tiroir d'audit et
verify.html** (le sceau se vérifie sur fichiers statiques). **La démo agent** passe en **rediffusion de runs réels**
(`replay.json`, enregistrés avec les vrais appels navette et les vrais hash, étiquetés comme tels) et le journal
affiche l'**instantané réel** pris au build. Rien de simulé, rien de cassé.

**Le jour où une API existe** (VPS, Render…) : `<meta name="slabb-api" content="https://api.slabb.dev">` dans
tech.html, `ALLOW_ORIGIN=https://slabb.dev npm start` côté serveur, `./deploy/pages.sh`, push — la démo redevient live.

**En local, toujours live** : `npm install && npm start` → http://127.0.0.1:8791 (autospawn navette).

Deux journaux, deux rôles : `seal-journal.jsonl` = le journal du **sceau des fichiers** (écrit par `tools/seal.py`) ;
`journal.jsonl` = le journal **des actes de l'agent** (écrit par le serveur, instantané sur Pages). Ils ne se touchent pas.

## Points à valider avant mise en ligne
- **AI Alliance non mentionnée** : aucune trace publique vérifiable (rien sur GitHub) tant que Sam ne fournit pas de lien (profil howcani, paper #130). Ajout en 30 s dès qu'il existe.
- « autour d'un café à Épinal » / « sans engagement » sur client.html : promesses commerciales à confirmer ou retirer.
- Localisation « Épinal (Vosges) » — une ligne par page si ça change.
- Email public : `github@slabb.dev`.
- Nom de boîte (S//ABB vs SLABB) volontairement absent.
- Compteur « 25 articles » et les 4 vedettes : tirés de l'API dev.to du 17/10/2026 — rafraîchir de temps en temps.
- Toggle FR/EN : i18n client-side inline, aucune persistance (pas de cookie ni localStorage — cohérent avec « zéro tracking »).
