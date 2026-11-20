#!/usr/bin/env python3
"""
Script d'Audit de Conformite et de Reponse a Incident (Srv-Prod-01)
Auteur : Anthony Mangin
"""
import os, sys, socket, hashlib
from datetime import datetime

# --- ELEMENTS D'INVESTIGATION ---
ip_attaquant = "185.199.108.42"
compte_compromis = "svc_deploy"
mdp_casse = "bastion2026"
code_api_extrait = "API-PROD-9941"

# --- CORRECTIONS DE CONFORMITE ---
# Remplacez 0 par le port standard du protocole HTTPS
port_https_standard = 443

# Passez ce booleen a True une fois la remediation effectuee
remediation_terminee = True

def verifier_permissions():
    fichiers = [
        ("1_journaux_siem/parefeu_waf.conf", 0o640, "rw-r-----"),
        ("1_journaux_siem/cle_tls_prod.key", 0o400, "r--------"),
        ("audit_remediation_soc.py", 0o700, "rwx------")
    ]
    for chemin, mode_attendu, label in fichiers:
        mode_actuel = os.stat(chemin).st_mode & 0o777
        if mode_actuel != mode_attendu:
            sys.exit(f"[-] Permissions non conformes sur '{chemin}' (attendu : {label}).")

def verifier_processus():
    for port in (13022, 13080):
        s = socket.socket()
        if s.connect_ex(("127.0.0.1", port)) == 0:
            s.close()
            sys.exit(f"[-] Un processus ecoute encore sur le port {port}.")
        s.close()

def generer_livrables():
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    rapport = f"""# Rapport d'Investigation SOC & Durcissement Systeme (Srv-Prod-01)

**Date de l'audit :** {date_str}  
**Analyste :** Anthony Mangin  
**Environnement :** Kali Linux / Serveur Linux Debian (`Srv-Prod-01`)  
**Statut :** Intrusion contenue, ecouteurs clandestins neutralises et systeme durci.

## 1. Synthese de l'Incident
L'analyse des journaux HTTP a mis en evidence une injection SQL (`UNION_SELECT`) aboutie (HTTP 200) depuis l'adresse IP `{ip_attaquant}`, suivie de l'exposition de services locaux sur les ports TCP `13022` et `13080` et de la compromission du compte `{compte_compromis}`.

## 2. Demarche d'Investigation & Remediation
- Analyse des journaux d'acces et identification des activites malveillantes (`401`, `403`, `404`, `200`).
- Forensique sur capture memoire, extraction de chaines, decodage multi-couches et audit des sockets reseau.
- Enumeration web, inspection du code client et requetage HTTP `POST` authentifie.
- Verification d'integrite `SHA-256`, cassage de hash `MD5` et requetage relationnel `SQLite`.
- Arret des processus actifs, application des permissions restrictives et verification automatisee.

## 3. Indicateurs de Compromission (IoC)
| Categorie | Valeur | Mesure |
| :--- | :--- | :--- |
| Adresse IP source (SQLi) | `{ip_attaquant}` | Blocage au niveau pare-feu / WAF |
| Ports locaux clandestins | `13022/tcp`, `13080/tcp` | Arret des processus |
| Compte compromis | `{compte_compromis}` | Rotation des acces et revocation (`{code_api_extrait}`) |
"""
    open("RAPPORT_INCIDENT_SOC.md", "w").write(rapport)

    encart_cv = f"""=======================================================================
   ENCART CV - RUBRIQUE PROJETS TECHNIQUES
=======================================================================
PROJET : Reponse a incident (DFIR) et durcissement d'un serveur Linux compromis
Environnement : Kali Linux, Python 3, SQLite, Bash, HTTP
- Investigation de journaux Web, detection d'une injection SQL aboutie et analyse forensique de captures memoire et de sockets reseau.
- Enumeration web, inspection de code client, forge de requetes HTTP authentifiees, controle d'integrite SHA-256, cassage de hash et requetes SQL.
- Neutralisation des processus clandestins, durcissement des permissions fichiers et automatisation de la generation du rapport d'incident.
=======================================================================
"""
    open("ENCART_CV.txt", "w").write(encart_cv)

if __name__ == "__main__":
    verifier_permissions()
    combinaison = f"{ip_attaquant.strip()}:{compte_compromis.strip()}:{mdp_casse.strip()}:{code_api_extrait.strip().upper()}:{port_https_standard}:{remediation_terminee}"
    if hashlib.sha256(combinaison.encode()).hexdigest() != "5b742a31a9de2f9aa810091addbed928da543c1fd7b816bbe6c0a13d056b2cca":
        sys.exit("[-] Echec de validation : verifiez les champs renseignes et les corrections du script.")
    verifier_processus()
    generer_livrables()
    print("[+] Livrables generes : RAPPORT_INCIDENT_SOC.md et ENCART_CV.txt")
