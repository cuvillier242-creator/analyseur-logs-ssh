#!/usr/bin/env python3
"""
Analyseur de logs SSH.

Utilisation :
    python analyse_logs.py exemples/auth.log
    python analyse_logs.py exemples/auth.log --seuil 5 --fenetre 10 --csv rapport.csv
"""

import argparse
import csv
import sys
from collections import Counter

from analyseur.detection import analyser
from analyseur.parser import lire_fichier


def afficher_rapport(evenements, alertes):
    types = Counter(e.type for e in evenements)
    print("=" * 60)
    print(" RAPPORT D'ANALYSE DES CONNEXIONS SSH")
    print("=" * 60)
    print(f"Événements analysés     : {len(evenements)}")
    print(f"Connexions réussies     : {types['succes']}")
    print(f"Échecs de mot de passe  : {types['echec']}")
    print(f"Utilisateurs inconnus   : {types['utilisateur_inconnu']}")

    top_ip = Counter(e.ip for e in evenements if e.type == "echec").most_common(5)
    if top_ip:
        print("\nIP avec le plus d'échecs :")
        for ip, nb in top_ip:
            print(f"  {ip:<16} {nb} échecs")

    print(f"\nAlertes : {len(alertes)}")
    print("-" * 60)
    for a in alertes:
        print(f"[{a.niveau:<8}] {a.regle} | {a.ip}\n            {a.details}")
    if not alertes:
        print("Aucune activité suspecte détectée.")


def exporter_csv(alertes, chemin):
    with open(chemin, "w", newline="", encoding="utf-8") as f:
        ecrivain = csv.writer(f)
        ecrivain.writerow(["niveau", "regle", "ip", "details"])
        for a in alertes:
            ecrivain.writerow([a.niveau, a.regle, a.ip, a.details])
    print(f"\nRapport exporté : {chemin}")


def main():
    p = argparse.ArgumentParser(description="Détecte les connexions SSH suspectes dans un fichier auth.log")
    p.add_argument("fichier", help="chemin du fichier de logs (ex. /var/log/auth.log)")
    p.add_argument("--seuil", type=int, default=5, help="nb d'échecs déclenchant l'alerte force brute (défaut 5)")
    p.add_argument("--fenetre", type=int, default=10, help="fenêtre de temps en minutes (défaut 10)")
    p.add_argument("--annee", type=int, help="année des logs (auth.log ne la contient pas)")
    p.add_argument("--csv", help="exporter les alertes dans un fichier CSV")
    args = p.parse_args()

    try:
        evenements = lire_fichier(args.fichier, args.annee)
    except FileNotFoundError:
        sys.exit(f"Erreur : fichier introuvable -> {args.fichier}")

    alertes = analyser(evenements, args.seuil, args.fenetre)
    afficher_rapport(evenements, alertes)
    if args.csv:
        exporter_csv(alertes, args.csv)
    # Code de sortie 1 s'il y a une alerte critique (utile dans un script automatisé).
    sys.exit(1 if any(a.niveau == "CRITIQUE" for a in alertes) else 0)


if __name__ == "__main__":
    main()
