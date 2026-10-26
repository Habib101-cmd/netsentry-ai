# API

Documentation interactive (OpenAPI) : http://localhost:8000/docs (mode développement). Toutes les routes, sauf `/health*`,
`/auth/login` et `/auth/refresh`, exigent un jeton `Authorization: Bearer ...`. Un compte dont le mot de passe doit être
changé ne peut utiliser que `/auth/change-password`, `/auth/me` et `/auth/logout`.

| Méthode et route                        | Rôle requis                      | Description                                                                 |
| --------------------------------------- | -------------------------------- | --------------------------------------------------------------------------- |
| POST `/auth/login`                      | public (débit limité)            | Connexion ; verrouillage après 5 échecs                                     |
| POST `/auth/refresh`                    | public (jeton de renouvellement) | Nouveau jeton (rotation)                                                    |
| POST `/auth/logout`                     | connecté                         | Révoque le jeton de renouvellement                                          |
| POST `/auth/change-password`            | connecté                         | Change le mot de passe (politique appliquée)                                |
| GET `/auth/me`                          | connecté                         | Utilisateur courant                                                         |
| GET, POST `/users`                      | admin                            | Liste, création de comptes                                                  |
| GET `/audit-logs`                       | admin                            | Journal d'audit (pagination)                                                |
| GET `/scopes`                           | admin, analyste                  | Périmètres autorisés                                                        |
| POST `/scopes`                          | admin                            | Crée un périmètre (confirmation d'autorisation obligatoire, journalisée)    |
| POST `/scans`                           | admin, analyste                  | Lance un scan (cible validée, profil parmi `discovery`, `standard`, `deep`) |
| GET `/scans`, `/scans/{id}`             | admin, analyste                  | Liste, détail                                                               |
| POST `/scans/{id}/cancel`               | admin, analyste                  | Annule un scan                                                              |
| GET `/scans/{id}/compare/{other_id}`    | admin, analyste                  | Comparaison (avant = `id`, après = `other_id`)                              |
| GET `/scans/{id}/map`                   | admin, analyste                  | Données de la carte du réseau                                               |
| GET `/scans/{id}/anomalies`             | admin, analyste                  | Comportements atypiques à vérifier                                          |
| GET `/scans/timeline`                   | admin, analyste                  | Chronologie (filtre `profile`)                                              |
| GET `/hosts`, `/hosts/{id}`             | admin, analyste                  | Équipements                                                                 |
| PATCH `/hosts/{id}`                     | admin, analyste                  | Criticité (`low`, `normal`, `high`)                                         |
| GET `/findings`, `/findings/summary`    | admin, analyste                  | Constats (filtres, pagination), synthèse                                    |
| GET `/findings/export?format=csv\|json` | admin, analyste                  | Export des constats                                                         |
| PATCH `/findings/{id}`                  | admin, analyste                  | Statut ; `accepted` exige un commentaire                                    |
| POST `/reports`, GET `/reports`         | admin, analyste                  | Génère, liste les rapports PDF                                              |
| GET `/reports/{id}/download`            | admin, analyste                  | Télécharge un rapport                                                       |
| GET `/health`, `/health/db`             | public                           | Santé de l'API et de la base                                                |
