"""Génère un faux fichier auth.log (données fictives) pour tester l'analyseur."""

import random
from datetime import datetime, timedelta

random.seed(42)
lignes = []
t = datetime(2026, 9, 14, 8, 0, 0)
pid = 1000


def ajouter(moment, message):
    global pid
    pid += 1
    lignes.append(f"{moment:%b %d %H:%M:%S} serveur sshd[{pid}]: {message}")


# Trafic normal : employés qui se connectent en journée, avec quelques fautes de frappe.
for _ in range(40):
    t += timedelta(minutes=random.randint(3, 15))
    user, ip = random.choice([("nicolas", "192.168.1.20"), ("marie", "192.168.1.21"), ("admin", "192.168.1.10")])
    if random.random() < 0.15:
        ajouter(t, f"Failed password for {user} from {ip} port {random.randint(40000, 60000)} ssh2")
    ajouter(t + timedelta(seconds=5), f"Accepted password for {user} from {ip} port {random.randint(40000, 60000)} ssh2")

# Attaque 1 : force brute sur root depuis 203.0.113.45 (sans succès).
a = datetime(2026, 9, 14, 11, 30, 0)
for i in range(25):
    ajouter(a + timedelta(seconds=i * 7), f"Failed password for root from 203.0.113.45 port {50000 + i} ssh2")

# Attaque 2 : test de noms d'utilisateur depuis 198.51.100.23.
b = datetime(2026, 9, 14, 14, 5, 0)
for i, nom in enumerate(["test", "oracle", "guest", "postgres", "ubuntu"]):
    ajouter(b + timedelta(seconds=i * 3), f"Invalid user {nom} from 198.51.100.23 port {51000 + i}")
    ajouter(b + timedelta(seconds=i * 3 + 1), f"Failed password for invalid user {nom} from 198.51.100.23 port {51000 + i} ssh2")

# Attaque 3 : mot de passe deviné, puis connexion à 2h du matin.
c = datetime(2026, 9, 15, 2, 10, 0)
for i in range(6):
    ajouter(c + timedelta(seconds=i * 20), f"Failed password for marie from 192.0.2.77 port {52000 + i} ssh2")
ajouter(c + timedelta(minutes=3), "Accepted password for marie from 192.0.2.77 port 52010 ssh2")

# Bruit : lignes d'autres services, ignorées par l'analyseur.
ajouter(datetime(2026, 9, 14, 9, 0, 0), "pam_unix(sshd:session): session opened for user nicolas")
lignes.append("Sep 14 09:00:01 serveur CRON[999]: (root) CMD (run-parts /etc/cron.hourly)")

lignes.sort(key=lambda l: datetime.strptime("2026 " + l[:15], "%Y %b %d %H:%M:%S"))
with open("auth.log", "w", encoding="utf-8") as f:
    f.write("\n".join(lignes) + "\n")
print(f"{len(lignes)} lignes écrites dans auth.log")
