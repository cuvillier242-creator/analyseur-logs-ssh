"""Règles de détection des connexions suspectes."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta


@dataclass
class Alerte:
    niveau: str      # "CRITIQUE", "ELEVE" ou "MOYEN"
    regle: str
    ip: str
    details: str


def force_brute(evenements, seuil=5, fenetre_minutes=10):
    """Règle 1 : une même IP échoue au moins `seuil` fois en `fenetre_minutes` minutes."""
    alertes = []
    fenetre = timedelta(minutes=fenetre_minutes)
    echecs_par_ip = defaultdict(deque)
    deja_signalees = set()

    for evt in evenements:
        if evt.type != "echec":
            continue
        file = echecs_par_ip[evt.ip]
        file.append(evt.horodatage)
        # On retire les échecs trop anciens (fenêtre glissante).
        while evt.horodatage - file[0] > fenetre:
            file.popleft()
        if len(file) >= seuil and evt.ip not in deja_signalees:
            deja_signalees.add(evt.ip)
            alertes.append(Alerte(
                "ELEVE", "Force brute", evt.ip,
                f"{seuil} échecs ou plus en moins de {fenetre_minutes} min (dès {file[0]:%d/%m %H:%M})",
            ))
    # On complète chaque alerte avec le nombre total d'échecs de l'IP.
    total = defaultdict(int)
    for evt in evenements:
        if evt.type == "echec":
            total[evt.ip] += 1
    for a in alertes:
        a.details += f", {total[a.ip]} échecs au total"
    return alertes


def succes_apres_echecs(evenements, seuil=3):
    """Règle 2 : une IP réussit à se connecter après plusieurs échecs (mot de passe peut-être deviné)."""
    alertes = []
    echecs = defaultdict(int)
    for evt in evenements:
        if evt.type == "echec":
            echecs[evt.ip] += 1
        elif evt.type == "succes":
            if echecs[evt.ip] >= seuil:
                alertes.append(Alerte(
                    "CRITIQUE", "Connexion réussie après échecs", evt.ip,
                    f"Compte '{evt.user}' ouvert après {echecs[evt.ip]} échecs, le {evt.horodatage:%d/%m à %H:%M}",
                ))
            echecs[evt.ip] = 0
    return alertes


def enumeration_comptes(evenements, seuil=3):
    """Règle 3 : une IP essaie plusieurs noms d'utilisateur qui n'existent pas."""
    comptes = defaultdict(set)
    for evt in evenements:
        if evt.type == "utilisateur_inconnu":
            comptes[evt.ip].add(evt.user)
    return [
        Alerte("MOYEN", "Test de comptes inexistants", ip,
               f"{len(noms)} comptes testés : {', '.join(sorted(noms))}")
        for ip, noms in comptes.items() if len(noms) >= seuil
    ]


def connexion_hors_horaires(evenements, debut=7, fin=20):
    """Règle 4 : connexion réussie en dehors des heures de travail."""
    return [
        Alerte("MOYEN", "Connexion hors horaires", evt.ip,
               f"Compte '{evt.user}' connecté le {evt.horodatage:%d/%m à %H:%M}")
        for evt in evenements
        if evt.type == "succes" and not (debut <= evt.horodatage.hour < fin)
    ]


ORDRE = {"CRITIQUE": 0, "ELEVE": 1, "MOYEN": 2}


def analyser(evenements, seuil_force_brute=5, fenetre_minutes=10):
    """Applique toutes les règles et trie les alertes de la plus grave à la moins grave."""
    alertes = (
        force_brute(evenements, seuil_force_brute, fenetre_minutes)
        + succes_apres_echecs(evenements)
        + enumeration_comptes(evenements)
        + connexion_hors_horaires(evenements)
    )
    return sorted(alertes, key=lambda a: ORDRE[a.niveau])
