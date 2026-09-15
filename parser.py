"""Lecture des logs SSH (format /var/log/auth.log) et extraction des événements."""

import re
from dataclasses import dataclass
from datetime import datetime

# Exemple de ligne :
# Sep 14 03:12:45 serveur sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52100 ssh2
ENTETE = re.compile(r"^(?P<date>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: (?P<message>.*)$")

MOTIFS = {
    "echec": re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"),
    "succes": re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"),
    "utilisateur_inconnu": re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"),
}


@dataclass
class Evenement:
    horodatage: datetime
    type: str   # "echec", "succes" ou "utilisateur_inconnu"
    user: str
    ip: str


def lire_ligne(ligne, annee):
    """Transforme une ligne de log en Evenement, ou renvoie None si elle ne nous intéresse pas."""
    entete = ENTETE.match(ligne.strip())
    if not entete:
        return None
    # auth.log n'indique pas l'année : on la fournit nous-mêmes.
    horodatage = datetime.strptime(f"{annee} {entete['date']}", "%Y %b %d %H:%M:%S")
    for type_evt, motif in MOTIFS.items():
        trouve = motif.search(entete["message"])
        if trouve:
            return Evenement(horodatage, type_evt, trouve["user"], trouve["ip"])
    return None


def lire_fichier(chemin, annee=None):
    """Lit un fichier de logs complet et renvoie la liste des événements SSH."""
    annee = annee or datetime.now().year
    evenements = []
    with open(chemin, encoding="utf-8", errors="replace") as fichier:
        for ligne in fichier:
            evt = lire_ligne(ligne, annee)
            if evt:
                evenements.append(evt)
    return evenements
