"""Tests automatiques. Lancer avec : python -m unittest discover tests"""

import unittest
from datetime import datetime, timedelta

from analyseur.detection import (connexion_hors_horaires, enumeration_comptes,
                                 force_brute, succes_apres_echecs)
from analyseur.parser import Evenement, lire_ligne

T0 = datetime(2026, 9, 14, 10, 0, 0)


def evt(minutes, type_evt, ip="10.0.0.1", user="root"):
    return Evenement(T0 + timedelta(minutes=minutes), type_evt, user, ip)


class TestParser(unittest.TestCase):
    def test_echec_utilisateur_inconnu(self):
        e = lire_ligne("Sep 14 03:12:45 srv sshd[12]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2", 2026)
        self.assertEqual((e.type, e.user, e.ip), ("echec", "admin", "1.2.3.4"))

    def test_succes(self):
        e = lire_ligne("Sep 14 09:00:00 srv sshd[12]: Accepted publickey for nicolas from 5.6.7.8 port 22 ssh2", 2026)
        self.assertEqual((e.type, e.user, e.horodatage.hour), ("succes", "nicolas", 9))

    def test_ligne_ignoree(self):
        self.assertIsNone(lire_ligne("Sep 14 09:00:01 srv CRON[9]: (root) CMD (ls)", 2026))


class TestDetection(unittest.TestCase):
    def test_force_brute_detectee(self):
        self.assertEqual(len(force_brute([evt(i, "echec") for i in range(5)], seuil=5, fenetre_minutes=10)), 1)

    def test_echecs_trop_espaces(self):
        # 5 échecs espacés de 5 minutes : jamais 5 dans la même fenêtre de 10 minutes.
        self.assertEqual(force_brute([evt(i * 5, "echec") for i in range(5)], seuil=5, fenetre_minutes=10), [])

    def test_succes_apres_echecs(self):
        alertes = succes_apres_echecs([evt(0, "echec"), evt(1, "echec"), evt(2, "echec"), evt(3, "succes")])
        self.assertEqual(alertes[0].niveau, "CRITIQUE")

    def test_enumeration(self):
        evts = [evt(0, "utilisateur_inconnu", user=u) for u in ("a", "b", "c")]
        self.assertEqual(len(enumeration_comptes(evts)), 1)

    def test_hors_horaires(self):
        nuit = Evenement(datetime(2026, 9, 14, 2, 0), "succes", "marie", "1.1.1.1")
        jour = Evenement(datetime(2026, 9, 14, 10, 0), "succes", "marie", "1.1.1.1")
        self.assertEqual(len(connexion_hors_horaires([nuit, jour])), 1)


if __name__ == "__main__":
    unittest.main()
