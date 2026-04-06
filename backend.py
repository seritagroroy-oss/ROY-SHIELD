import asyncio
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
import tldextract
import whois
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()

APP_VERSION = "2.1"
APP_ENV = os.getenv("ROY_SHIELD_ENV", "development")
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ROY_SHIELD_ALLOWED_ORIGINS", "*").split(",")
    if origin.strip()
]
FETCH_TIMEOUT = float(os.getenv("ROY_SHIELD_FETCH_TIMEOUT", "8"))
SSL_TIMEOUT = float(os.getenv("ROY_SHIELD_SSL_TIMEOUT", "5"))

app = FastAPI(title="ROY SHIELD API", version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

FREE_HOSTING = [
    "netlify.app",
    "github.io",
    "vercel.app",
    "glitch.me",
    "replit.dev",
    "weebly.com",
    "wix.com",
    "blogspot.com",
    "wordpress.com",
    "sites.google.com",
    "000webhostapp.com",
    "infinityfreeapp.com",
    "bsite.net",
    "freehostia.com",
    "x10host.com",
    "byethost",
    "freehosting",
    "hostfree",
]

RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "buzz", "xyz", "top", "click", "link", "work", "date"}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "shorte.st",
    "bc.vc",
    "clk.sh",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
}

TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "netflix.com",
    "wikipedia.org",
    "github.com",
    "stackoverflow.com",
    "reddit.com",
    "paypal.com",
    "orange.com",
    "mtn.com",
    "orange.ci",
    "wave.com",
    "moov.ci",
    "gouv.ci",
    "impots.ci",
    "tresor.ci",
    "bceao.int",
}

SUSPICIOUS_KEYWORDS_URL = [
    ("urgent", 15),
    ("urgence", 15),
    ("paiement", 12),
    ("payment", 12),
    ("recrute", 12),
    ("recrutement", 12),
    ("frais", 15),
    ("promo", 8),
    ("gagner", 12),
    ("winner", 10),
    ("gratuit", 8),
    ("cadeau", 10),
    ("gift", 10),
    ("verify", 12),
    ("verif", 12),
    ("confirm", 10),
    ("login", 8),
    ("password", 10),
    ("bank", 12),
    ("banque", 12),
    ("paypal", 15),
    ("amazon", 12),
    ("mtn", 8),
    ("moov", 8),
    ("wave", 6),
    ("orange", 6),
]

SUSPICIOUS_CONTENT_KEYWORDS = [
    "mot de passe",
    "password",
    "identifiant",
    "numero de telephone",
    "numéro de téléphone",
    "frais d'inscription",
    "frais de dossier",
    "virement",
    "western union",
    "moneygram",
    "paiement immediat",
    "paiement immédiat",
    "offre limitee",
    "offre limitée",
    "ne ratez pas",
    "felicitations",
    "félicitations",
    "vous avez gagne",
    "vous avez gagné",
    "cliquez maintenant",
    "remplissez le formulaire",
    "envoyez vos informations",
    "compte bancaire",
    "carte de credit",
    "carte de crédit",
    "cvv",
    "code secret",
    "recrutement urgent",
    "emploi immediat",
    "emploi immédiat",
    "sans experience",
    "sans expérience",
    "travail a domicile",
    "travail à domicile",
    "gain facile",
]

AFRICA_BLACKLIST = [
    "mtn-ci-promo",
    "orange-money-ci",
    "wave-transfert",
    "recrutement-ci",
    "emploi-abidjan",
    "bourse-etude-ci",
    "visa-ci",
    "concours-mtn",
    "concours-orange",
    "tresor-ci",
    "douane-ci",
    "cnps-ci",
    "cie-ci",
    "sodeci",
    "moov-money",
    "airtel-money",
    "momo-gratuit",
    "ivoirjob",
    "ci-emploi",
    "emploi-dakar",
    "emploi-mali",
    "recrutement-senegal",
]

BRAND_TYPOSQUAT = {
    "paypal": ["paypa1", "pay-pal", "paypai", "paypall", "paypal-ci", "paypal-secure"],
    "orange": ["0range", "orang3", "orange-ci-money", "orangemoney-ci", "orange-money"],
    "mtn": ["mtn-ci", "mtn-money", "mtnci", "m-t-n", "mtn2", "mtnpromo"],
    "wave": ["waave", "wave-ci", "wave-money", "wavemoney", "wave-transfert"],
    "amazon": ["amaz0n", "amazzon", "amazon-promo", "amazon-ci", "amazonn"],
    "google": ["g00gle", "gooogle", "googIe", "google-ci", "googlesecure"],
    "microsoft": ["micros0ft", "microsooft", "microsoft-secure", "micr0soft"],
    "apple": ["appIe", "app1e", "apple-id-secure", "apple-verify"],
    "facebook": ["faceb00k", "facebok", "facebook-ci", "face-book"],
    "instagram": ["instagr4m", "instagran", "instagram-ci", "insta-gram"],
    "whatsapp": ["whatsap", "whatsapp-ci", "whatssapp", "whatsapp-promo"],
    "linkedin": ["linkedln", "linke-din", "linkedin-job"],
    "moov": ["m00v", "moov-ci", "moov-money", "moovcash"],
}


class ScanRequest(BaseModel):
    url: str


def levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    return dp[m][n]


def normalize_input_url(raw_url: str) -> str:
    cleaned = raw_url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    return cleaned


def check_typosquat(hostname: str):
    core = re.sub(r"^www\.", "", hostname).split(".")[0].lower()
    for brand, variants in BRAND_TYPOSQUAT.items():
        for variant in variants:
            if variant in hostname:
                return brand, variant
        if core != brand and len(core) > 3 and levenshtein(core, brand) == 1:
            return brand, core
    return None, None


def check_ssl(hostname: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=SSL_TIMEOUT),
            server_hostname=hostname,
        )
        cert = conn.getpeercert()
        conn.close()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        return {"valid": True, "days_left": days_left, "subject": dict(x[0] for x in cert.get("subject", []))}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


def get_whois_info(domain: str) -> dict:
    try:
        result = whois.whois(domain)
        creation = result.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            return {
                "found": True,
                "age_days": age_days,
                "registrar": result.registrar or "Inconnu",
                "creation": str(creation)[:10],
            }
        return {"found": True, "age_days": None, "registrar": result.registrar or "Inconnu"}
    except Exception:
        return {"found": False}


async def fetch_page_content(url: str) -> dict:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120 Safari/537.36"
        )
    }
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=FETCH_TIMEOUT) as client:
            response = await client.get(url, headers=headers)
            return {
                "ok": True,
                "status": response.status_code,
                "html": response.text[:50000],
                "final_url": str(response.url),
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def analyze_html_content(html: str, original_url: str, final_url: str) -> list:
    signals = []
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=" ", strip=True).lower()

    found_keywords = [keyword for keyword in SUSPICIOUS_CONTENT_KEYWORDS if keyword.lower() in text]
    if found_keywords:
        signals.append(
            {
                "type": "danger" if len(found_keywords) >= 3 else "warn",
                "icon": "x" if len(found_keywords) >= 3 else "warn",
                "label": f"{len(found_keywords)} mot(s) suspect(s) dans le contenu de la page",
                "detail": "Mots detectes : " + ", ".join(f'"{keyword}"' for keyword in found_keywords[:6]),
                "source": "python",
            }
        )

    forms = soup.find_all("form")
    password_inputs = soup.find_all("input", {"type": "password"})
    if password_inputs:
        signals.append(
            {
                "type": "danger",
                "icon": "x",
                "label": "Formulaire de collecte de mot de passe detecte",
                "detail": (
                    f"La page contient {len(password_inputs)} champ(s) mot de passe. "
                    "Risque eleve de phishing."
                ),
                "source": "python",
            }
        )
    elif forms:
        signals.append(
            {
                "type": "warn",
                "icon": "warn",
                "label": f"{len(forms)} formulaire(s) detecte(s) sur la page",
                "detail": "La page collecte des informations. Verifiez ce qui est demande avant de remplir.",
                "source": "python",
            }
        )

    legal_keywords = [
        "mentions legales",
        "mentions légales",
        "politique de confidentialite",
        "politique de confidentialité",
        "conditions d'utilisation",
        "privacy policy",
        "terms of service",
        "contact",
    ]
    if not any(keyword in text for keyword in legal_keywords):
        signals.append(
            {
                "type": "warn",
                "icon": "warn",
                "label": "Aucune mention legale detectee",
                "detail": "Le site ne contient pas de mentions legales ni de politique de confidentialite visibles.",
                "source": "python",
            }
        )

    if original_url != final_url:
        original_host = urlparse(original_url).netloc
        final_host = urlparse(final_url).netloc
        if original_host != final_host:
            signals.append(
                {
                    "type": "danger",
                    "icon": "x",
                    "label": "Redirection vers un domaine different",
                    "detail": (
                        f"Le lien redirige de {original_host} vers {final_host}. "
                        "Technique courante de dissimulation."
                    ),
                    "source": "python",
                }
            )

    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else ""
    for brand in ["paypal", "orange", "mtn", "wave", "amazon", "apple", "microsoft", "facebook", "google"]:
        if brand in title.lower() and brand not in urlparse(original_url).netloc.lower():
            signals.append(
                {
                    "type": "danger",
                    "icon": "x",
                    "label": f'Titre de page usurpe la marque "{brand}"',
                    "detail": f'Le titre affiche "{title}" mais le domaine n appartient pas a {brand}.',
                    "source": "python",
                }
            )
            break

    return signals


async def analyze_scan(raw_url: str) -> dict:
    normalized_url = normalize_input_url(raw_url)

    try:
        parsed = urlparse(normalized_url)
    except Exception:
        return {"error": "URL invalide"}

    hostname = parsed.netloc.lower().split(":")[0]
    if not hostname:
        return {"error": "URL invalide"}

    ext = tldextract.extract(normalized_url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    tld = ext.suffix.split(".")[-1] if ext.suffix else ""
    full_url_lower = normalized_url.lower()

    result = {
        "url": normalized_url,
        "score": 0,
        "signals": [],
        "python_signals": [],
        "whois": {},
        "ssl": {},
        "content_analyzed": False,
    }

    trusted_match = next((item for item in TRUSTED_DOMAINS if hostname == item or hostname.endswith("." + item)), None)
    if trusted_match:
        result["signals"].append(
            {
                "type": "safe",
                "icon": "check",
                "label": "Domaine de confiance reconnu",
                "detail": f"{trusted_match} est un domaine officiel verifie.",
                "source": "python",
            }
        )
        result["verdict"] = "Site fiable"
        result["level"] = "safe"
        return result

    for pattern in AFRICA_BLACKLIST:
        if pattern in full_url_lower:
            result["score"] += 50
            result["python_signals"].append(
                {
                    "type": "danger",
                    "icon": "x",
                    "label": "Arnaque africaine connue detectee",
                    "detail": f'Pattern "{pattern}" reference dans la base locale ROY SHIELD.',
                    "source": "python",
                }
            )
            break

    brand, variant = check_typosquat(hostname)
    if brand:
        result["score"] += 40
        result["python_signals"].append(
            {
                "type": "danger",
                "icon": "x",
                "label": f'Typosquatting detecte - imitation de "{brand}"',
                "detail": f'"{variant}" imite la marque officielle "{brand}".',
                "source": "python",
            }
        )

    if not normalized_url.startswith("https://"):
        result["score"] += 25
        result["python_signals"].append(
            {
                "type": "danger",
                "icon": "x",
                "label": "Connexion non securisee (HTTP)",
                "detail": "Le site n utilise pas HTTPS. Vos donnees peuvent etre interceptees.",
                "source": "python",
            }
        )
    else:
        ssl_info = check_ssl(hostname)
        result["ssl"] = ssl_info
        if not ssl_info["valid"]:
            result["score"] += 20
            result["python_signals"].append(
                {
                    "type": "danger",
                    "icon": "x",
                    "label": "Certificat SSL invalide ou absent",
                    "detail": f'Erreur SSL : {ssl_info.get("error", "inconnu")}.',
                    "source": "python",
                }
            )
        elif ssl_info.get("days_left", 999) < 15:
            result["score"] += 10
            result["python_signals"].append(
                {
                    "type": "warn",
                    "icon": "warn",
                    "label": f'Certificat SSL expire dans {ssl_info["days_left"]} jour(s)',
                    "detail": "Un certificat bientot expire peut indiquer un site peu maintenu.",
                    "source": "python",
                }
            )
        else:
            result["python_signals"].append(
                {
                    "type": "safe",
                    "icon": "check",
                    "label": f'Certificat SSL valide ({ssl_info.get("days_left", "?")} jours restants)',
                    "detail": "La connexion est chiffree et le certificat est valide.",
                    "source": "python",
                }
            )

    free_hit = next((item for item in FREE_HOSTING if hostname.endswith(item) or item in hostname), None)
    if free_hit:
        result["score"] += 30
        result["python_signals"].append(
            {
                "type": "danger",
                "icon": "x",
                "label": "Hebergement gratuit detecte",
                "detail": f'"{free_hit}" est souvent utilise pour des arnaques rapides.',
                "source": "python",
            }
        )

    if tld in RISKY_TLDS:
        result["score"] += 20
        result["python_signals"].append(
            {
                "type": "danger",
                "icon": "x",
                "label": f"Extension de domaine risquee (.{tld})",
                "detail": f".{tld} est une extension frequemment utilisee pour des arnaques.",
                "source": "python",
            }
        )

    if next((item for item in URL_SHORTENERS if hostname.endswith(item) or item in hostname), None):
        result["score"] += 30
        result["python_signals"].append(
            {
                "type": "danger",
                "icon": "x",
                "label": "Lien raccourci - destination masquee",
                "detail": "Ce type de lien masque la destination finale.",
                "source": "python",
            }
        )

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
        result["score"] += 35
        result["python_signals"].append(
            {
                "type": "danger",
                "icon": "x",
                "label": "Adresse IP directe utilisee",
                "detail": "Les sites legitimes utilisent en general un nom de domaine.",
                "source": "python",
            }
        )

    parts = hostname.split(".")
    if len(parts) > 3:
        result["score"] += 15
        result["python_signals"].append(
            {
                "type": "warn",
                "icon": "warn",
                "label": f"Sous-domaine complexe ({len(parts) - 2} niveau(x))",
                "detail": "Plusieurs niveaux de sous-domaines peuvent masquer le vrai domaine.",
                "source": "python",
            }
        )

    url_for_keywords = full_url_lower.replace("https://", "").replace("http://", "")
    matched_keywords = []
    for keyword, score in SUSPICIOUS_KEYWORDS_URL:
        if keyword in url_for_keywords and keyword not in [item[0] for item in matched_keywords]:
            result["score"] += score
            matched_keywords.append((keyword, score))
    if matched_keywords:
        total_keyword_score = sum(score for _, score in matched_keywords)
        result["python_signals"].append(
            {
                "type": "danger" if total_keyword_score > 30 else "warn",
                "icon": "x" if total_keyword_score > 30 else "warn",
                "label": f"{len(matched_keywords)} mot(s) suspect(s) dans l URL",
                "detail": "Mots detectes : " + ", ".join(f'"{keyword}"' for keyword, _ in matched_keywords[:6]),
                "source": "python",
            }
        )

    whois_info = await asyncio.to_thread(get_whois_info, domain)
    result["whois"] = whois_info
    if whois_info["found"] and whois_info.get("age_days") is not None:
        age = whois_info["age_days"]
        if age < 30:
            result["score"] += 35
            result["python_signals"].append(
                {
                    "type": "danger",
                    "icon": "x",
                    "label": f"Domaine tres recent ({age} jour(s))",
                    "detail": f'Cree le {whois_info.get("creation", "?")}.',
                    "source": "python",
                }
            )
        elif age < 180:
            result["score"] += 15
            result["python_signals"].append(
                {
                    "type": "warn",
                    "icon": "warn",
                    "label": f"Domaine recent ({age} jours)",
                    "detail": "Ce domaine a moins de six mois.",
                    "source": "python",
                }
            )
        else:
            result["python_signals"].append(
                {
                    "type": "safe",
                    "icon": "check",
                    "label": f"Domaine ancien ({age} jours)",
                    "detail": f'Enregistre chez {whois_info.get("registrar", "Inconnu")}.',
                    "source": "python",
                }
            )
    elif not whois_info["found"]:
        result["score"] += 10
        result["python_signals"].append(
            {
                "type": "warn",
                "icon": "warn",
                "label": "Informations WHOIS introuvables",
                "detail": "Impossible de recuperer les donnees d enregistrement du domaine.",
                "source": "python",
            }
        )

    page = await fetch_page_content(normalized_url)
    if page["ok"]:
        result["content_analyzed"] = True
        content_signals = analyze_html_content(page["html"], normalized_url, page["final_url"])
        for signal in content_signals:
            if signal["type"] == "danger":
                result["score"] += 20
            elif signal["type"] == "warn":
                result["score"] += 8
        result["python_signals"].extend(content_signals)
    else:
        result["python_signals"].append(
            {
                "type": "warn",
                "icon": "warn",
                "label": "Contenu de la page inaccessible",
                "detail": f'Impossible de charger la page : {page.get("error", "erreur inconnue")}',
                "source": "python",
            }
        )

    result["score"] = min(result["score"], 100)
    if result["score"] >= 60:
        result["verdict"] = "Arnaque probable"
        result["level"] = "danger"
    elif result["score"] >= 30:
        result["verdict"] = "Site suspect"
        result["level"] = "warn"
    else:
        result["verdict"] = "Site fiable"
        result["level"] = "safe"

    return result


@app.post("/scan")
async def scan(req: ScanRequest):
    return await analyze_scan(req.url)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": APP_VERSION,
        "environment": APP_ENV,
        "allowed_origins": ALLOWED_ORIGINS or ["*"],
    }
