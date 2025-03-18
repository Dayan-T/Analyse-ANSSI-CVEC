Description du Projet
Ce script Python a pour objectif d'extraire, d'enrichir et d'analyser des données relatives
aux vulnérabilités (CVE - Common Vulnerabilities and Exposures) provenant de diverses
sources, telles que les flux RSS d'ANSSI, le site Mitre CVE et l'API EPSS (Exploit
Prediction Scoring System). Les données enrichies sont visualisées sous forme de
graphiques et peuvent être envoyées par e-mail aux opérateurs concernés.
Fonctionnalités
1. Extraction des données de vulnérabilités :
o Récupération des flux RSS d'ANSSI (« avis » et « alertes »).
o Extraction des CVE associées pour enrichissement.
2. Enrichissement des données CVE :
o Obtention des détails CVE depuis l'API Mitre (Description, Score CVSS,
Type CWE, etc.).
o Récupération des scores EPSS associés via l'API EPSS.
o Catégorisation des vulnérabilités en fonction des scores CVSS.
3. Analyse et visualisation :
o Histogrammes pour la distribution des scores CVSS.
o Courbes pour l'évolution des scores EPSS.
o Diagrammes circulaires pour la répartition des types CWE.
o Classements des éditeurs et produits les plus affectés.
o Boxplots montrant la dispersion des scores CVSS par éditeur.
4. Envoi d'alertes par email :
o Transmission des informations CVE aux opérateurs via e-mail.
Installation
Prérequis
• Python 3.x
• Bibliothèques Python requises :
o requests
o feedparser
o pandas
o matplotlib
o seaborn
o smtplib et email.mime (fournies avec Python standard).
Installation des dépendances
Exécutez la commande suivante pour installer les dépendances :
pip install requests feedparser pandas matplotlib seaborn
Configuration de l'environnement
1. Créez un fichier texte nommé liste_de_cve.txt contenant une liste de CVE à
analyser (un CVE par ligne).
2. Remplissez le dictionnaire destinataires avec les adresses email des opérateurs
associés à chaque éditeur.
Utilisation
Extraction et enrichissement
• Lancez le script pour extraire et enrichir les données des vulnérabilités :
python <nom_du_script>.py
• Les données enrichies seront enregistrées dans un fichier CSV nommé
enrichissement_general.csv.
Visualisation
• Les visualisations des données enrichies (diagrammes et histogrammes) seront
affichées.
Envoi d'emails
• Les informations sur les vulnérabilités seront envoyées par email aux opérateurs
définis dans le dictionnaire destinataires.
Structure des Fonctions
1. extraction_anssi_data
• Récupère les flux RSS d'ANSSI (« avis » et « alertes »).
• Retourne une liste de dictionnaires contenant les titres, descriptions, liens et
types d'alertes.
2. extraction_cve
• Parcourt les données extraites d'ANSSI.
• Récupère les CVE associées à partir des liens des flux RSS.
3. enrich_cve_mitre
• Enrichit les CVE avec des informations détaillées depuis l’API Mitre :
o Description
o Score CVSS
o Type CWE
o Produits et versions affectés.
4. enrich_cve_epss
• Récupère les scores EPSS pour prédire la probabilité d’exploitation d’une
vulnérabilité.
5. enrichissement_general
• Combine les données Mitre et EPSS pour générer un dictionnaire consolidé des
informations pour un CVE donné.
6. creation_visuelle
• Génère des visualisations des données enrichies :
o Histogrammes, courbes, diagrammes circulaires, boxplots, etc.
7. envoyer_email
• Envoie par email les détails des CVE aux opérateurs concernés.
Fichiers Générés
1. enrichissement_general.csv :
o Contient toutes les informations enrichies sur les CVE.
2. Visualisations :
o Graphiques affichés à l’écran pour analyse.
Améliorations Possibles
1. Ajouter des gestionnaires d'erreurs pour chaque étape critique (en particulier
pour les appels API).
2. Utiliser un fichier de configuration pour centraliser les paramètres (flux RSS, emails, etc.).
3. Automatiser la planification du script avec des outils comme cron ou Task
Scheduler.
4. Enregistrer les graphiques sous forme de fichiers image (PNG ou PDF).
