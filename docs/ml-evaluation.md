# Évaluation du module d'anomalies (Machine Learning)

Document généré par `python -m app.ai_engine.evaluate` : les chiffres ci-dessous sont reproductibles.

## Principe

- Modèle : Isolation Forest (scikit-learn), 200 arbres, graine fixe. Version : `iforest-1-skl1.9.1-seed42`.
- Données **synthétiques** (un laboratoire réel de 10 à 20 machines ne fournit pas assez d'historique) : 15 hôtes, 8 semaines à raison d'un scan par jour (56 scans), avec variations bénignes (hôte injoignable 2 % du temps, port non vu 1 % du temps, service ajouté ou retiré durablement dans 2 % des couples hôte/scan : sans ces évolutions bénignes, les caractéristiques « nouveaux services » et « services inhabituels » seraient constantes à 0 et l'Isolation Forest ne pourrait pas s'en servir).
- **Entraînement** : simulation graine 42, sans aucune anomalie. **Évaluation** : simulation distincte (graine 7), 21 scans d'historique puis injection d'anomalies étiquetées. Aucune observation n'est partagée entre les deux jeux.
- Seuil : score au-delà du quantile 98 % des scores d'entraînement (taux de faux positifs visé : 2 %).
- Anomalies injectées (persistantes, étiquetées à leur première observation) : nouvel hôte, nouveau port, service inhabituel, hausse brutale du nombre de ports.

## Caractéristiques (par hôte et par scan)

| Caractéristique | Définition |
|---|---|
| open_ports | nombre de ports ouverts |
| identified_services | nombre de services ouverts dont le nom est identifié |
| new_services | ports ouverts absents du profil de référence (union des 3 scans précédents) |
| hosts_delta | variation relative du nombre d'hôtes actifs par rapport au scan précédent |
| change_freq | part des 5 dernières transitions où l'ensemble des ports de l'hôte a changé |
| unusual_ratio | part des services ouverts dont le nom n'a jamais été vu sur cet hôte (référence) |

## Résultats sur le jeu d'évaluation (562 observations, 15 anomalies)

| Système | Précision | Rappel | Taux de faux positifs | Faux positifs | Faux négatifs |
|---|---|---|---|---|---|
| Règles seules (comparaison de scans) | 24.2 % | 100.0 % | 8.6 % | 47 | 0 |
| ML seul (Isolation Forest) | 31.0 % | 86.7 % | 5.3 % | 29 | 2 |
| Règles ET ML (changement confirmé comme atypique) | 44.8 % | 86.7 % | 2.9 % | 16 | 2 |
| Règles OU ML (union) | 20.0 % | 100.0 % | 11.0 % | 60 | 0 |

### Détection par type d'anomalie (anomalies détectées / injectées)

| Type | Injectées | Règles | ML | Règles ET ML |
|---|---|---|---|---|
| new_host | 3 | 3 | 3 | 3 |
| new_port | 2 | 2 | 0 | 0 |
| unusual_service | 3 | 3 | 3 | 3 |
| port_spike | 7 | 7 | 7 | 7 |

### Robustesse : moyenne sur 10 simulations d'évaluation indépendantes

| Système | Précision | Rappel | Taux de faux positifs | Faux positifs (moy.) | Faux négatifs (moy.) |
|---|---|---|---|---|---|
| Règles seules (comparaison de scans) | 28.6 % | 100.0 % | 7.0 % | 40.8 | 0.0 |
| ML seul (Isolation Forest) | 42.9 % | 86.5 % | 3.6 % | 21.2 | 2.1 |
| Règles ET ML (changement confirmé comme atypique) | 66.9 % | 86.5 % | 1.3 % | 7.7 | 2.1 |
| Règles OU ML (union) | 23.6 % | 100.0 % | 9.3 % | 54.3 | 0.0 |

## Lecture honnête des résultats

- Les anomalies sont injectées par nous : les règles de comparaison les voient par construction (un nouvel hôte ou un nouveau port est toujours un changement). Un rappel élevé des règles n'est donc pas une surprise.
- L'apport mesurable du ML est de **filtrer** les changements anodins (port qui réapparaît après une indisponibilité, hôte de retour) : voir la ligne « Règles ET ML » et la baisse des faux positifs.
- Les anomalies sont rares (de l'ordre de 3 % des observations) : la précision est mécaniquement faible pour tous les systèmes, et un seul jeu d'évaluation en contient peu (quelques dizaines). La moyenne sur plusieurs simulations est plus fiable.
- Contrepartie : le ML peut manquer les anomalies discrètes (ex. un seul nouveau port d'un service déjà connu sur l'hôte), car un tel changement ressemble à une évolution bénigne. C'est visible dans le tableau par type.
- Le ML ne sait pas qu'un service précis (telnet, RDP...) est risqué : il ne voit que sa nouveauté. Les règles de risque (étape 7) restent indispensables.

## Limites

- Données synthétiques : un vrai réseau a d'autres régularités. Le modèle est adapté à un laboratoire et doit être réentraîné sur un historique réel avant tout usage opérationnel.
- Le modèle ne voit que des comptages de ports et de services, pas le contenu du trafic.
- Une anomalie est un **comportement atypique à vérifier** : ce n'est ni une vulnérabilité, ni une attaque confirmée.
- Au moins 2 scans précédents (même cible, même profil, hors découverte rapide) sont nécessaires.
