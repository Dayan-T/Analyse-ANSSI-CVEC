# Projet Python
# %% Import des librairies
import feedparser
import requests
import re
import pandas as pd
import time
import os
import pickle
import plotly.express as px
from email.mime.text import MIMEText
import smtplib

# %% Extraction des URLs JSON depuis le flux RSS
url_rss = [
    "https://www.cert.ssi.gouv.fr/avis/feed",
    "https://www.cert.ssi.gouv.fr/alerte/feed",
]


def extract_json_urls(rss_urls):
    json_data = []
    for rss_url in rss_urls:
        rss_feed = feedparser.parse(rss_url)
        for entry in rss_feed.entries:
            if "link" in entry:
                json_url = entry.link + "/json/"
                json_data.append(
                    {
                        "title": entry.title,
                        "type": "Alerte" if "alerte" in entry.link else "Avis",
                        "date": entry.published,
                        "link": entry.link,
                        "json_url": json_url,
                    }
                )
    print(f"{len(json_data)} URLs JSON extraites : {json_data}")
    return json_data


def save_data(filename, data):
    with open(filename, "wb") as file:
        pickle.dump(data, file)


def load_data(filename):
    if os.path.exists(filename):
        with open(filename, "rb") as file:
            return pickle.load(file)
    return None


# %% Extraction des CVE depuis les fichiers JSON
def extract_cve_from_json(json_data):
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_dict = {}
    total_cve_count = 0  # compteur de CVE
    unique_cves = set()  # ensemble pour stocker les CVE uniques

    for entry in json_data:
        try:
            response = requests.get(entry["link"] + "/json/")
            data = response.json()
            cves = re.findall(cve_pattern, str(data))
            for cve in cves:
                if cve not in unique_cves:
                    unique_cves.add(cve)
                    cve_dict[cve] = {
                        "Titre ANSSI": entry["title"],
                        "Type": entry["type"],
                        "Date": entry["date"],
                        "CVE": cve,
                        "Lien": entry["link"],
                    }
            total_cve_count += len(cves)  # CVE trouvées
            time.sleep(2)  # Respecter un délai pour éviter de surcharger le serveur
        except Exception as e:
            print(f"Erreur lors de l'extraction des CVE depuis {entry['link']} : {e}")

    print(f"Nombre total de CVE trouvées : {total_cve_count}")  # nombre total de CVE
    print(
        f"Nombre de CVE uniques trouvées : {len(unique_cves)}"
    )  # nombre de CVE uniques
    return list(cve_dict.values())


# %% Enrichissement des données CVE
def fetch_cve_data(cve_list):
    enriched_data = []
    for cve_entry in cve_list:
        print(f"Enrichissement des données pour la CVE : {cve_entry['CVE']}")
        try:
            cve = cve_entry["CVE"]
            # API CVE
            url_cve = f"https://cveawg.mitre.org/api/cve/{cve}"
            response_cve = requests.get(url_cve)
            data_cve = response_cve.json()

            parsed_cve = parse_cve(cve_entry, data_cve)
            enriched_data.extend(parsed_cve)
        except Exception as e:
            print(f"Erreur lors de l'enrichissement de {cve} : {e}")
        time.sleep(2)  # Respecter un délai entre les requêtes
    print(f"{len(enriched_data)} entrées enrichies générées.")

    return enriched_data


def parse_cve(cve_entry, data_cve):
    problem_types = (
        data_cve.get("containers", {}).get("cna", {}).get("problemTypes", [{}])[0]
    )
    products = get_products(data_cve)
    description = get_description(data_cve)
    cwe = get_cwe(problem_types)
    cwe_description = get_cwe_description(problem_types)
    epss_score = get_epss_score(cve_entry["CVE"])
    cna_cvss = extract_cvss_from_cna(data_cve)
    adp_cvss = extract_cvss_from_adp(data_cve)
    cvss = adp_cvss if adp_cvss is not None else cna_cvss
    cvss_score = get_cvss_severity(cvss)
    cvss_value = cvss["baseScore"] if cvss else "Non disponible"

    entries = []
    for product in products:
        enriched_entry = cve_entry.copy()
        enriched_entry.update(
            {
                "Description": description,
                "CVSS": cvss_value,
                "Base Severity": f"{cvss_score} ({cvss_value})",
                "CWE": cwe,
                "CWE Description": cwe_description,
                "EPSS": epss_score,
                "Produit/Vendor": f"{product['Product']} / {product['Vendor']}",
                "Versions": product["Versions"],
            }
        )

        entries.append(enriched_entry)

    return entries


def get_products(data_cve):
    affected = data_cve.get("containers", {}).get("cna", {}).get("affected", [])
    products = []

    for product in affected:
        vendor = product.get("vendor", "Non disponible")
        product_name = product.get("product", "Non disponible")
        versions = [
            v.get("version", "Non disponible")
            for v in product.get("versions", [])
            if v.get("status") == "affected"
        ]
        products.append(
            {
                "Vendor": vendor,
                "Product": product_name,
                "Versions": ", ".join(versions),
            }
        )
    print(f"Produits affectés : {products}")

    return products


def get_description(data_cve):
    description = (
        data_cve.get("containers", {})
        .get("cna", {})
        .get("descriptions", [{}])[0]
        .get("value", "Non valide")
    )
    return description


def get_cwe(problem_types):
    cwe = problem_types.get("descriptions", [{}])[0].get("cweId", "Non disponible")
    return cwe


def get_cwe_description(problem_types):
    cwe_description = problem_types.get("descriptions", [{}])[0].get(
        "description", "Non disponible"
    )
    return cwe_description


def get_epss_score(cve):
    # API EPSS
    url_epss = f"https://api.first.org/data/v1/epss?cve={cve}"
    response_epss = requests.get(url_epss)
    epss_data = response_epss.json()["data"]
    epss_score = epss_data[0] if epss_data else "Non disponible"

    return epss_score


def extract_cvss_from_cna(data_cve):
    metrics = data_cve.get("containers", {}).get("cna", {}).get("metrics", [])
    cvss = extract_cvss(metrics)

    return cvss


def extract_cvss_from_adp(data_cve):
    all_metrics = data_cve.get("containers", {}).get("adp", [{}])
    for i in range(len(all_metrics)):
        metrics = all_metrics[i].get("metrics", [])
        cvss = extract_cvss(metrics)
        if cvss is not None:
            return cvss

    return None


def extract_cvss(metrics):
    for metric in metrics:
        for key, value in metric.items():
            cvss = re.findall(r"cvssV[^\s]*", key)
            if cvss:
                return value

    return None


def get_cvss_severity(cvss_score):
    if cvss_score == None:
        return "Non disponible"

    parsed_cvss = float(cvss_score["baseScore"])
    if parsed_cvss >= 9:
        return "Critique"
    elif parsed_cvss >= 7:
        return "Élevée"
    elif parsed_cvss >= 4:
        return "Moyenne"
    else:
        return "Faible"


# Visualisation des données
def visualize_data(df):
    print("\nCréation des visualisations avec Plotly...")

    # on utilise map pour transformer les valeurs de la colonne CVSS en numérique
    severity_mapping = {
        "Critique": 9,
        "Élevée": 7,
        "Moyenne": 4,
        "Faible": 1,
        "Non disponible": None,
    }

    # on applique le mapping
    df["CVSS_Score"] = df["CVSS"].map(severity_mapping)

    # Distribution des scores CVSS avec noms et valeurs "Non disponible"
    fig_cvss = px.histogram(
        df,
        x="CVSS",
        title="Distribution des scores CVSS",
        labels={"CVSS": "Type de CVSS"},
        color_discrete_sequence=["#636EFA"],
    )
    fig_cvss.update_layout(
        yaxis_title="Fréquence", title_font_size=18, template="plotly_dark"
    )
    fig_cvss.write_html("cvss_distribution_names.html")
    fig_cvss.show()

    # Séparation pour éviter tout problème de longueur (et éventuels warnings)
    df["CVSS_Score"] = pd.to_numeric(df["CVSS_Score"], errors="coerce")
    df.dropna(subset=["CVSS_Score"], inplace=True)

    # Distribution numérique des scores CVSS après le mapping
    fig_cvss_numeric = px.histogram(
        df,
        x="CVSS_Score",
        nbins=10,
        title="Distribution des scores CVSS",
        labels={"CVSS_Score": "Score CVSS"},
    )
    fig_cvss_numeric.update_layout(
        yaxis_title="Fréquence", title_font_size=18, template="plotly_dark"
    )
    fig_cvss_numeric.write_html("cvss_distribution_numeric.html")
    fig_cvss_numeric.show()

    # Répartition des types de CWE avec graph en bar
    cwe_counts = df["CWE"].value_counts().reset_index()
    cwe_counts.columns = ["CWE", "Count"]
    fig_cwe = px.bar(
        cwe_counts,
        x="CWE",
        y="Count",
        title="Répartition des types de CWE",
        color="Count",
        labels={"CWE": "CWE", "Count": "Nombre de cas"},
        color_continuous_scale="Viridis",
    )
    fig_cwe.update_layout(
        title_font_size=18,
        xaxis_title="CWE",
        yaxis_title="Nombre de cas",
        template="plotly_dark",
    )
    fig_cwe.write_html("cwe_distribution.html")
    fig_cwe.show()

    # on classe les produits les plus affectés avec des couleurs
    product_counts = df["Produit/Vendor"].value_counts().head(10).reset_index()
    product_counts.columns = ["Produit/Vendor", "Count"]
    fig_products = px.bar(
        product_counts,
        x="Count",
        y="Produit/Vendor",
        orientation="h",
        title="Top 10 des produits/vendors les plus affectés",
        labels={
            "Count": "Nombre de vulnérabilités",
            "Produit/Vendor": "Produit/Vendor",
        },
        color="Count",
        color_continuous_scale="Viridis",
    )
    fig_products.update_layout(title_font_size=18, template="plotly_dark")
    fig_products.write_html("top_products.html")
    fig_products.show()


# fonction pour générer des alertes
def generate_alerts(df):
    # Mapping des valeurs CVSS
    severity_mapping = {
        "Critique": 9,
        "Élevée": 7,
        "Moyenne": 4,
        "Faible": 1,
        "Non disponible": None,
    }
    if df["CVSS"].dtype == "object":
        df["CVSS"] = df["CVSS"].map(
            severity_mapping
        )  # on map les valeurs de la colonne CVSS si c'est un objet (string)

    # on drop les lignes avec des valeurs NaN dans CVSS
    df = df.dropna(subset=["CVSS"])
    df["CVSS"] = pd.to_numeric(
        df["CVSS"], errors="coerce"
    )  # coerce pour remplacer les valeurs invalides par NaN

    # on prend que les cve critiques donc avec un score de 9 ou plus
    critical_cves = df[df["CVSS"] >= 9]
    print("Valeurs uniques dans la colonne CVSS :", df["CVSS"].unique())
    print("Lignes critiques détectées :", critical_cves)

    alert_count = 0

    if not critical_cves.empty:
        print(f"\n{len(critical_cves)} vulnérabilités critiques détectées.")
        print("\nGénération des alertes pour les vulnérabilités critiques...")
        for _, row in critical_cves.iterrows():  # _ pour ignorer l'index
            alert_message = (
                f"Alerte critique pour {row['CVE']} : {row['Description']}\n"
            )
            print(alert_message)
            for email in email_subscribers:
                send_email(
                    to_email=email,
                    subject=f"Critique : {row['CVE']} détectée",
                    body=alert_message,
                )
                alert_count += 1

    print(f"Nombre total d'alertes envoyées : {alert_count}")


# fonction qui envoie les mails
def send_email(to_email, subject, body):
    try:
        from_email = "esilvprojet@gmail.com"
        password = "klqd aypv kqek oydn"

        msg = MIMEText(body)
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print(f"Email envoyé à {to_email}")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email : {e}")


# Liste des abonnés
email_subscribers = ["esilvprojet@gmail.com"]

# %% Programme principal
if __name__ == "__main__":
    # Fichiers de sauvegarde
    json_urls_file = "json_urls.pkl"
    cve_list_file = "cve_list.pkl"
    enriched_data_file = "enriched_data.pkl"

    # Extraction des URLs JSON
    print("Début de l'extraction des URLs JSON...")
    json_data = load_data(json_urls_file)
    if json_data is None:
        json_data = extract_json_urls(url_rss)
        save_data(json_urls_file, json_data)
    print(f"Nombre total d'URLs JSON extraites : {len(json_data)}")

    # Extraction des CVE
    print("Début de l'extraction des CVE...")
    cve_list = load_data(cve_list_file)
    if cve_list is None:
        cve_list = extract_cve_from_json(json_data)
        save_data(cve_list_file, cve_list)
    print(f"Nombre total de CVE extraites : {len(cve_list)}")

    # Enrichissement des données CVE
    print("Enrichissement des données en cours...")
    enriched_cve_data = load_data(enriched_data_file)
    if enriched_cve_data is None:
        enriched_cve_data = fetch_cve_data(cve_list)
        save_data(enriched_data_file, enriched_cve_data)
    print(f"Nombre total d'entrées enrichies : {len(enriched_cve_data)}")

    # Création du DataFrame et export vers Excel
    excel_file = "cve_enriched_data_complete.xlsx"

    if os.path.exists(excel_file):
        print(f"On supprime l'ancien fichier {excel_file}")
        os.remove(excel_file)
        print("Fichier supprimé")
    else:
        print(f"Le fichier {excel_file} n'existe pas")

    df = pd.DataFrame(enriched_cve_data)
    print("Enrichissement terminé. Voici un aperçu des données consolidées :")
    print(df.head())
    df.to_excel(excel_file, index=False)

    print("Début des visualisations...")
    visualize_data(df)

    print("Début de la génération des alertes...")
    generate_alerts(df)
