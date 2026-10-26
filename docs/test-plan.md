# Plan de tests

| Type                             | Fichiers                                                                                                         | Ce qui est vérifié                                                                                                                                           |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Unitaires                        | `test_target_validation`, `test_nmap`, `test_risk_engine`, `test_compare`, `test_netmap`, `test_password_policy` | Validation des cibles, commande Nmap, parsing XML, règles et score, comparaison, carte, mots de passe                                                        |
| Intégration (API + base de test) | `test_auth`, `test_security`, `test_report`, `test_ai_engine`                                                    | Parcours complets de l'API, rapport PDF, anomalies enregistrées                                                                                              |
| Sécurité                         | `test_security`                                                                                                  | Jetons falsifiés, rôles, injections (commande, SQL, XSS), cibles hors périmètre, entrées malformées, XML hostile, CORS, en-têtes, limitation de débit, audit |
| Performance                      | `tests/perf/measure_latency.py`                                                                                  | ENF-02 : p95 < 500 ms pendant un scan                                                                                                                        |
| Machine Learning                 | `test_ai_engine`, `docs/ml-evaluation.md`                                                                        | Évaluation sur jeu distinct, comparaison règles / règles + ML                                                                                                |
| Laboratoire (manuel)             | `docs/demo.md`                                                                                                   | CA-04, CA-07, CA-11 sur de vrais scans                                                                                                                       |

Les tests de sécurité ont été validés par **mutation** : en cassant volontairement une protection (CORS ouvert,
commentaire d'acceptation supprimé, requête SQL concaténée, rôle retiré), le test correspondant échoue.

**Limite** : le scénario de scan complet (API + worker + Nmap + laboratoire) est manuel ; il n'est pas lancé en CI
(il demanderait Docker dans Docker).

## Commandes

```powershell
docker compose run --rm --no-deps -v "${PWD}/backend:/code" backend sh -c "pip install -q -r requirements-dev.txt && python -m pytest -q --cov=app --cov-report=term-missing"
```

## Mesure ENF-02 (à compléter)

Date : ... · Commande : `python backend\tests\perf\measure_latency.py --user ... --launch deep` · p95 : ... ms · Scan en cours pendant la mesure : oui / non

## Critères d'acceptation

| Critère                   | Preuve                                                                             |
| ------------------------- | ---------------------------------------------------------------------------------- |
| CA-01 Démarrage           | `docker compose up` depuis un clone neuf (README)                                  |
| CA-02 Authentification    | `test_auth` (balayage de toutes les routes), `test_security`                       |
| CA-03 Périmètre           | `test_target_validation`, `test_security` (cibles rejetées avant tout scan)        |
| CA-04 Découverte          | Scan du laboratoire comparé à `lab/expected_results.md`                            |
| CA-05 Stockage            | Redémarrage des conteneurs, résultats conservés                                    |
| CA-06 Analyse des risques | `test_risk_engine`, constats avec preuves sur le laboratoire                       |
| CA-07 Comparaison         | `test_compare`, scénario `docs/demo.md`                                            |
| CA-08 Rapport             | `test_report`, PDF de démonstration                                                |
| CA-09 IA                  | `docs/ml-evaluation.md`, `test_ai_engine`                                          |
| CA-10 Qualité             | CI verte, pip-audit / npm audit / Trivy sans critique non traitée, gitleaks propre |
| CA-11 Fiabilité           | Annulation et échec d'un scan sans altérer les résultats précédents                |
| CA-12 Audit               | `test_sensitive_actions_are_audited`, page Administration                          |
