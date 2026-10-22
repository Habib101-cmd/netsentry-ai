# NetSentry AI

Outil d'analyse de réseau (Nmap) avec moteur de risques, rapports PDF et journal d'audit.

## Lancement

1. Copier la configuration, puis remplacer les valeurs `change_me` (mot de passe base de données et `SECRET_KEY`) :

   ```
   copy .env.example .env
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

2. Démarrer le laboratoire de test (il crée le réseau `netsentry_lab`) :

   ```
   docker compose -f lab/docker-compose.lab.yml up -d
   ```

3. Démarrer l'application :

   ```
   docker compose up --build
   ```

4. Créer le compte administrateur :

   ```
   docker compose exec backend python -m app.scripts.create_admin
   ```

5. Ouvrir http://localhost:8080 (API : http://localhost:8000/docs).

## Tests

```
cd backend
pip install -r requirements.txt
python -m pytest
```

## Avertissement

N'analysez que des réseaux pour lesquels vous avez une autorisation explicite.
