# Analyseur de logs SSH – détection de connexions suspectes

Outil en Python (sans bibliothèque externe) qui lit un fichier de logs SSH Linux (`/var/log/auth.log`) et signale les connexions suspectes, classées par niveau de gravité.

## Ce que l'outil détecte

| Règle | Niveau | Exemple |
|---|---|---|
| Connexion réussie après plusieurs échecs | CRITIQUE | Un mot de passe a peut-être été deviné |
| Force brute | ÉLEVÉ | 5 échecs ou plus depuis la même IP en 10 minutes |
| Test de comptes inexistants | MOYEN | Une IP essaie `test`, `oracle`, `guest`… |
| Connexion hors horaires | MOYEN | Connexion réussie à 2 h du matin |

## Installation

Il faut seulement Python 3.8 ou plus.

```bash
git clone https://github.com/<ton-pseudo>/analyseur-logs-ssh.git
cd analyseur-logs-ssh
```

## Utilisation

```bash
# 1. Générer un fichier de logs fictif pour tester
python exemples/generer_logs.py

# 2. Lancer l'analyse
python analyse_logs.py exemples/auth.log --annee 2026

# Options
python analyse_logs.py exemples/auth.log --seuil 3 --fenetre 5 --csv rapport.csv
```

Sur un vrai serveur Linux : `sudo python analyse_logs.py /var/log/auth.log`

Le programme renvoie le code de sortie `1` si une alerte critique est trouvée, ce qui permet de l'utiliser dans un script automatisé (par exemple avec cron).

## Exemple de résultat

```
Alertes : 6
------------------------------------------------------------
[CRITIQUE] Connexion réussie après échecs | 192.0.2.77
            Compte 'marie' ouvert après 6 échecs, le 15/09 à 02:13
[ELEVE   ] Force brute | 203.0.113.45
            5 échecs ou plus en moins de 10 min (dès 14/09 11:30), 25 échecs au total
[MOYEN   ] Test de comptes inexistants | 198.51.100.23
            5 comptes testés : guest, oracle, postgres, test, ubuntu
```

## Structure du projet

```
analyse_logs.py          # point d'entrée : options, rapport, export CSV
analyseur/parser.py      # lecture des lignes de log avec des expressions régulières
analyseur/detection.py   # les 4 règles de détection
exemples/generer_logs.py # création de logs fictifs (trafic normal + 3 attaques)
tests/test_detection.py  # tests automatiques
```

## Tests

```bash
python -m unittest discover tests
```

## Comment ça marche

1. **Lecture** : chaque ligne est découpée avec des expressions régulières (`re`) pour en extraire la date, le type d'événement, l'utilisateur et l'adresse IP.
2. **Force brute** : une fenêtre glissante (`deque`) garde les échecs récents de chaque IP ; si elle contient au moins `seuil` échecs, une alerte est créée.
3. **Tri** : les alertes sont classées de la plus grave à la moins grave, puis affichées ou exportées en CSV.

## Pistes d'amélioration

- Lire les logs au format `journalctl`
- Géolocaliser les adresses IP
- Générer automatiquement une règle de blocage (`iptables` / `fail2ban`)
- Envoyer une alerte par e-mail

*Les adresses IP des exemples sont des adresses de documentation réservées (RFC 5737) : aucune donnée réelle n'est utilisée.*
