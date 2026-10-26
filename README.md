# NetSentry AI

Analyseur de sécurité réseau : découverte des équipements (Nmap), analyse de risques explicable, comparaison de scans,
détection de comportements atypiques (Isolation Forest) et rapports PDF.

> **Usage légal uniquement.** À n'utiliser que sur des réseaux dont vous êtes propriétaire ou pour lesquels vous avez
> une autorisation écrite. Analyse non destructive : aucune exploitation, aucun déni de service, aucune force brute.
> Développement et démonstrations dans le laboratoire isolé fourni.

## Fonctionnalités

- Authentification (administrateur / analyste), jetons courts, journal d'audit, verrouillage des comptes.
- Périmètres autorisés, validation de chaque cible avant scan, profils de scan prédéfinis (aucune option libre).
- Constats avec preuves, score de risque explicable (0 à 100), statut « accepté » avec commentaire obligatoire.
- Comparaison de deux scans, chronologie, carte du réseau (relations observées / supposées).
- Comportements atypiques à vérifier (ML, données synthétiques, évaluation documentée).
- Rapports PDF, exports CSV / JSON.

## Prérequis

Docker Desktop (Compose v2). Pour développer : Python 3.12, Node 22.

## Démarrage rapide

```powershell
copy .env.example .env                                   # puis modifier les mots de passe et SECRET_KEY
docker compose -f lab/docker-compose.lab.yml up -d       # laboratoire isolé (réseau netsentry_lab)
docker compose up -d --build
docker compose run --rm backend python -m app.scripts.create_admin
```

Ouvrir **https://localhost:8443** (certificat auto-signé : accepter l'avertissement du navigateur).
Premier compte : changement de mot de passe obligatoire. Puis : Administration → Périmètres → créer `172.30.0.0/24`,
et Scans → lancer un scan.

Mode développement (API sur http://localhost:8000, Swagger sur /docs) : `docker compose up -d` charge
automatiquement `docker-compose.override.yml`. Mode « production » (seul le proxy est exposé) :
`docker compose -f docker-compose.yml up -d`.

## Tests et qualité

```powershell
docker compose run --rm --no-deps -v "${PWD}/backend:/code" backend sh -c "pip install -q -r requirements-dev.txt && python -m pytest -q --cov=app"
```

CI GitHub Actions : black, ruff, pytest (couverture ≥ 70 %), bandit, pip-audit, npm audit, gitleaks, Trivy.

## Documentation

`docs/architecture.md` · `docs/security.md` · `docs/api.md` · `docs/test-plan.md` · `docs/ml-evaluation.md` · `docs/demo.md`

## Limites connues

- Un scan reflète un instant et un point de vue réseau : il ne prouve jamais qu'un réseau est sûr.
- Les CVE rapprochées par version sont « potentielles » (faux positifs possibles).
- Le module d'anomalies est entraîné sur des données synthétiques : valeur indicative (voir `docs/ml-evaluation.md`).
- Pas de MFA, une seule organisation, pas de haute disponibilité.

## Licence

MIT.
