# Rapport d'Investigation SOC & Durcissement Systeme (Srv-Prod-01)

**Date de l'audit :** 2026-11-20 17:16  
**Analyste :** Anthony Mangin  
**Environnement :** Kali Linux / Serveur Linux Debian (`Srv-Prod-01`)  
**Statut :** Intrusion contenue, ecouteurs clandestins neutralises et systeme durci.

## 1. Synthese de l'Incident
L'analyse des journaux HTTP a mis en evidence une injection SQL (`UNION_SELECT`) aboutie (HTTP 200) depuis l'adresse IP `185.199.108.42`, suivie de l'exposition de services locaux sur les ports TCP `13022` et `13080` et de la compromission du compte `svc_deploy`.

## 2. Demarche d'Investigation & Remediation
- Analyse des journaux d'acces et identification des activites malveillantes (`401`, `403`, `404`, `200`).
- Forensique sur capture memoire, extraction de chaines, decodage multi-couches et audit des sockets reseau.
- Enumeration web, inspection du code client et requetage HTTP `POST` authentifie.
- Verification d'integrite `SHA-256`, cassage de hash `MD5` et requetage relationnel `SQLite`.
- Arret des processus actifs, application des permissions restrictives et verification automatisee.

## 3. Indicateurs de Compromission (IoC)
| Categorie | Valeur | Mesure |
| :--- | :--- | :--- |
| Adresse IP source (SQLi) | `185.199.108.42` | Blocage au niveau pare-feu / WAF |
| Ports locaux clandestins | `13022/tcp`, `13080/tcp` | Arret des processus |
| Compte compromis | `svc_deploy` | Rotation des acces et revocation (`API-PROD-9941`) |
# portfolio-cas-concret-1
