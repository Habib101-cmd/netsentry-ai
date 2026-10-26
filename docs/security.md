## Choix réseau du worker

- Option retenue : le worker rejoint le réseau Docker `netsentry_lab` (bridge, internal) en plus du réseau interne de la base. Pas de network_mode: host, pas de macvlan.
- Droits : cap_drop ALL, cap_add NET_RAW + NET_ADMIN (capacités posées sur le binaire nmap via setcap, NMAP_PRIVILEGED=1), utilisateur non root (uid 1000), système de fichiers en lecture seule, 512 Mo / 1 CPU.
- Risques : un bug dans le worker pourrait émettre des paquets bruts vers le labo ; atténué par la revalidation de la cible, la liste blanche d'options et l'absence d'accès Internet (réseaux internal).
- Alternatives : macvlan (pour scanner un vrai LAN), network_mode: host (déconseillé : expose le réseau de l'hôte).

## Mise en œuvre des exigences de sécurité

| ID     | Mesure                                                                                                                                                            | Preuve                                                                               |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| SEC-01 | Cible contenue dans un périmètre actif, plages interdites (loopback, link-local, multicast), taille max /22, adresse publique refusée sauf autorisation explicite | `test_target_validation`, `test_security`                                            |
| SEC-02 | Profils prédéfinis, options Nmap en liste blanche, appel par liste d'arguments sans shell                                                                         | `test_nmap_command_is_a_list_from_a_whitelist`, `test_scan_profile_is_a_closed_list` |
| SEC-03 | Worker : `cap_drop: ALL`, `NET_RAW` et `NET_ADMIN` seulement, utilisateur non root, lecture seule, 768 Mo / 1 CPU                                                 | `docker inspect` du conteneur                                                        |
| SEC-04 | Services séparés : proxy, frontend, backend, worker, base                                                                                                         | `docker-compose.yml`                                                                 |
| SEC-05 | PostgreSQL sur un réseau `internal`, aucun port publié                                                                                                            | `docker compose ps`                                                                  |
| SEC-06 | Secrets dans `.env` (ignoré par Git) ; gitleaks en CI                                                                                                             | `git ls-files .env` vide, CI                                                         |
| SEC-07 | Schémas Pydantic, limites de taille, pagination bornée, limitation de débit sur la connexion, CORS strict                                                         | `test_security`                                                                      |
| SEC-08 | Journal d'audit des connexions, créations, scans, rapports, exports                                                                                               | `test_sensitive_actions_are_audited`                                                 |
| SEC-09 | Délai maximal par scan (1800 s), 5 scans actifs au plus, annulation                                                                                               | `test_scan_queue_is_limited`, scénario d'annulation                                  |
| SEC-10 | Tests de permissions et d'entrées malformées                                                                                                                      | `test_security` (validés par mutation)                                               |
| SEC-11 | Argon2id, 12 caractères minimum, refus des mots de passe courants et de leurs variantes, verrouillage après 5 échecs                                              | `test_auth`, `test_password_policy`                                                  |
| SEC-12 | `defusedxml` (XXE, entités), taille limitée à 20 Mo                                                                                                               | `test_hostile_or_malformed_xml_is_rejected`                                          |
| SEC-13 | ORM paramétré ; React échappe l'affichage ; export CSV neutralisant les formules                                                                                  | `test_sql_injection_attempts_change_nothing`, `test_csv_export_neutralizes_formulas` |
| SEC-14 | En-têtes de sécurité (backend et proxy), HTTPS via Caddy (certificat auto-signé)                                                                                  | `test_security_headers_are_present`, `curl -k`                                       |
| SEC-15 | Aucune sortie brute de scan conservée ; `*.xml` ignoré par Git                                                                                                    | `.gitignore`, modèle de données                                                      |
| SEC-16 | pip-audit, npm audit, Trivy (version épinglée) en CI                                                                                                              | `.github/workflows/ci.yml`                                                           |

## Audit v1.2.0 (à compléter après exécution de la section C.7)

| Contrôle               | Date | Résultat | Action |
| ---------------------- | ---- | -------- | ------ |
| gitleaks               |      |          |        |
| bandit (moyen et plus) |      |          |        |
| pip-audit              |      |          |        |
| npm audit              |      |          |        |
| Trivy (images)         |      |          |        |

## Chaîne d'approvisionnement

Les versions des outils de sécurité sont épinglées. Trivy a subi une compromission en mars 2026 (versions 0.69.4 à 0.69.6,
tags de `trivy-action` détournés) : la CI utilise l'image 0.72.0 et jamais `trivy-action`. Dependabot propose les mises à jour.
La liste de mots de passe courants provient de SecLists (licence MIT).

## Risques résiduels et limites

- Le jeton de renouvellement est conservé dans `sessionStorage` : une faille XSS pourrait le voler. Atténuation : React
  échappe tout, aucun `dangerouslySetInnerHTML`, en-tête CSP du frontend.
- Jetons signés en HS256 avec un secret partagé ; pas d'authentification multifacteur.
- La limitation de débit est en mémoire (un seul processus backend).
- `--forwarded-allow-ips='*'` : acceptable parce que le backend n'est joignable que via le proxy, sauf en mode
  développement (port 8000 ouvert), où l'en-tête `X-Forwarded-For` pourrait être falsifié.
- Le worker garde `NET_ADMIN` et `NET_RAW` (exigés par certains scans Nmap) ; il n'a aucun accès à Internet sur le
  réseau du laboratoire.
- L'acceptation de l'avertissement légal est journalisée **à la création de chaque périmètre** ; à la première connexion,
  l'avertissement est affiché mais son acceptation n'est pas journalisée séparément (écart avec le cahier des charges §1.5).
- Les anomalies ML reposent sur des données synthétiques et ne remplacent pas l'analyse humaine.
