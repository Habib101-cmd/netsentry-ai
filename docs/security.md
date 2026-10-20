## Choix réseau du worker

- Option retenue : le worker rejoint le réseau Docker `netsentry_lab` (bridge, internal) en plus du réseau interne de la base. Pas de network_mode: host, pas de macvlan.
- Droits : cap_drop ALL, cap_add NET_RAW + NET_ADMIN (capacités posées sur le binaire nmap via setcap, NMAP_PRIVILEGED=1), utilisateur non root (uid 1000), système de fichiers en lecture seule, 512 Mo / 1 CPU.
- Risques : un bug dans le worker pourrait émettre des paquets bruts vers le labo ; atténué par la revalidation de la cible, la liste blanche d'options et l'absence d'accès Internet (réseaux internal).
- Alternatives : macvlan (pour scanner un vrai LAN), network_mode: host (déconseillé : expose le réseau de l'hôte).
