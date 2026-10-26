# Scénario de démonstration (environ 10 minutes)

Préparation : stack et laboratoire démarrés, administrateur créé, périmètre `172.30.0.0/24` défini.

1. **Connexion** : avertissement légal, changement de mot de passe obligatoire.
2. **Référence** : trois scans « Standard » sur `172.30.0.0/24`. Équipements, services, constats (preuves, détail du score).
3. **Modifications** :
   ```powershell
   docker compose -f lab/docker-compose.lab.yml stop ftp1
   $ports = @(8000, 8001) + (8081..8090)
   $ports | ForEach-Object { "server { listen $_; return 200 ""lab""; }" } | Set-Content -Encoding ascii lab\spike.conf
   docker cp lab\spike.conf netsentry-lab-web1-1:/etc/nginx/conf.d/spike.conf
   docker exec netsentry-lab-web1-1 nginx -s reload
   ```
4. **Quatrième scan « Standard »**, puis :
   - **Historique** : `172.30.0.13` ne répond plus (mention de la limite), 12 nouveaux ports sur `172.30.0.11` ;
   - **Carte** : relations observées et supposées, avec la mention de la limite ;
   - **Anomalies** : `web1` en « comportement atypique à vérifier », explication par caractéristique ;
   - **Constats** : nouveaux constats HTTP, statut « accepté » avec commentaire obligatoire.
5. **Rapport PDF** de ce scan : 10 sections, limites, comparaison, anomalies, aucune affirmation de sécurité.
6. **Administration** : journal d'audit (connexions, périmètres, scans, exports).
7. **Nettoyage** :
   ```powershell
   docker compose -f lab/docker-compose.lab.yml start ftp1
   docker exec netsentry-lab-web1-1 rm /etc/nginx/conf.d/spike.conf
   docker exec netsentry-lab-web1-1 nginx -s reload
   ```

Captures à réaliser pour le portfolio : connexion, tableau de bord, scan en cours, détail d'un constat avec son score,
carte, comparaison, anomalies, première page et section 10 du PDF, journal d'audit, GitHub Actions au vert.
Vidéo de 2 à 3 minutes : étapes 4 à 6.
