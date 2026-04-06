import re
import ssl
import socket
import hashlib
import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
import whois
import tldextract
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="ROY SHIELD API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

FREE_HOSTING = [
    "netlify.app", "github.io", "vercel.app", "glitch.me", "replit.dev",
    "weebly.com", "wix.com", "blogspot.com", "wordpress.com", "sites.google.com",
    "000webhostapp.com", "infinityfreeapp.com", "bsite.net", "freehostia.com",
    "x10host.com", "byethost", "freehosting", "hostfree",
]

RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "buzz", "xyz", "top", "click", "link", "work", "date"}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "bc.vc", "clk.sh", "rb.gy",
    "cutt.ly", "shorturl.at", "tiny.cc",
}

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "microsoft.com",
    "apple.com", "amazon.com", "netflix.com", "wikipedia.org",
    "github.com", "stackoverflow.com", "reddit.com", "paypal.com",
    "orange.com", "mtn.com", "orange.ci", "wave.com", "moov.ci",
    "gouv.ci", "impots.ci", "tresor.ci", "bceao.int",
}

SUSPICIOUS_KEYWORDS_URL = [
    ("urgent", 15), ("urgence", 15), ("paiement", 12), ("payment", 12),
    ("recrute", 12), ("recrutement", 12), ("frais", 15), ("promo", 8),
    ("gagner", 12), ("winner", 10), ("gratuit", 8), ("cadeau", 10),
    ("gift", 10), ("verify", 12), ("verif", 12), ("confirm", 10),
    ("login", 8), ("password", 10), ("bank", 12), ("banque", 12),
    ("paypal", 15), ("amazon", 12), ("mtn", 8), ("moov", 8),
    ("wave", 6), ("orange", 6),
]

SUSPICIOUS_CONTENT_KEYWORDS = [
    "mot de passe", "password", "identifiant", "numéro de téléphone",
    "frais d'inscription", "frais de dossier", "virement", "western union",
    "moneygram", "paiement immédiat", "offre limitée", "ne ratez pas",
    "félicitations", "vous avez gagné", "cliquez maintenant",
    "remplissez le formulaire", "envoyez vos informations",
    "compte bancaire", "carte de crédit", "cvv", "code secret",
    "recrutement urgent", "emploi immédiat", "sans expérience",
    "travail à domicile", "gain facile",
]

AFRICA_BLACKLIST = [
    "mtn-ci-promo", "orange-money-ci", "wave-transfert", "recrutement-ci",
    "emploi-abidjan", "bourse-etude-ci", "visa-ci", "concours-mtn",
    "concours-orange", "tresor-ci", "douane-ci", "cnps-ci", "cie-ci",
    "sodeci", "moov-money", "airtel-money", "momo-gratuit", "ivoirjob",
    "ci-emploi", "emploi-dakar", "emploi-mali", "recrutement-senegal",
]

BRAND_TYPOSQUAT = {
    "paypal":    ["paypa1", "pay-pal", "paypai", "paypall", "paypal-ci", "paypal-secure"],
    "orange":    ["0range", "orang3", "orange-ci-money", "orangemoney-ci", "orange-money"],
    "mtn":       ["mtn-ci", "mtn-money", "mtnci", "m-t-n", "mtn2", "mtnpromo"],
    "wave":      ["waave", "wave-ci", "wave-money", "wavemoney", "wave-transfert"],
    "amazon":    ["amaz0n", "amazzon", "amazon-promo", "amazon-ci", "amazonn"],
    "google":    ["g00gle", "gooogle", "googIe", "google-ci", "googlesecure"],
    "microsoft": ["micros0ft", "microsooft", "microsoft-secure", "micr0soft"],
    "apple":     ["appIe", "app1e", "apple-id-secure", "apple-verify"],
    "facebook":  ["faceb00k", "facebok", "facebook-ci", "face-book"],
    "instagram": ["instagr4m", "instagran", "instagram-ci", "insta-gram"],
    "whatsapp":  ["whatsap", "whatsapp-ci", "whatssapp", "whatsapp-promo"],
    "linkedin":  ["linkedln", "linke-din", "linkedin-job"],
    "moov":      ["m00v", "moov-ci", "moov-money", "moovcash"],
}


def levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1): dp[i][0] = i
    for j in range(n + 1): dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            dp[i][j] = dp[i-1][j-1] if a[i-1] == b[j-1] else 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    return dp[m][n]


def check_typosquat(hostname: str):
    core = re.sub(r"^www\.", "", hostname).split(".")[0].lower()
    for brand, variants in BRAND_TYPOSQUAT.items():
        for v in variants:
            if v in hostname:
                return brand, v
        if core != brand and len(core) > 3 and levenshtein(core, brand) == 1:
            return brand, core
    return None, None


def check_ssl(hostname: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname)
        cert = conn.getpeercert()
        conn.close()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        return {"valid": True, "days_left": days_left, "subject": dict(x[0] for x in cert.get("subject", []))}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def get_whois_info(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            return {"found": True, "age_days": age_days, "registrar": w.registrar or "Inconnu", "creation": str(creation)[:10]}
        return {"found": True, "age_days": None, "registrar": w.registrar or "Inconnu"}
    except Exception:
        return {"found": False}


async def fetch_page_content(url: str) -> dict:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
    }
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=8) as client:
            resp = await client.get(url, headers=headers)
            return {"ok": True, "status": resp.status_code, "html": resp.text[:50000], "final_url": str(resp.url)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def analyze_html_content(html: str, original_url: str, final_url: str) -> list:
    signals = []
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=" ", strip=True).lower()

    found_keywords = [kw for kw in SUSPICIOUS_CONTENT_KEYWORDS if kw.lower() in text]
    if found_keywords:
        signals.append({
            "type": "danger" if len(found_keywords) >= 3 else "warn",
            "icon": "x" if len(found_keywords) >= 3 else "warn",
            "label": f"{len(found_keywords)} mot(s) suspect(s) dans le contenu de la page",
            "detail": "Mots détectés : " + ", ".join(f'"{k}"' for k in found_keywords[:6]),
            "source": "python"
        })

    forms = soup.find_all("form")
    password_inputs = soup.find_all("input", {"type": "password"})
    if password_inputs:
        signals.append({
            "type": "danger", "icon": "x",
            "label": "Formulaire de collecte de mot de passe détecté",
            "detail": f"La page contient {len(password_inputs)} champ(s) mot de passe. Risque élevé de phishing.",
            "source": "python"
        })
    elif forms:
        signals.append({
            "type": "warn", "icon": "warn",
            "label": f"{len(forms)} formulaire(s) détecté(s) sur la page",
            "detail": "La page collecte des informations. Vérifiez ce qui est demandé avant de remplir.",
            "source": "python"
        })

    has_legal = any(kw in text for kw in ["mentions légales", "politique de confidentialité", "conditions d'utilisation", "privacy policy", "terms of service", "contact"])
    if not has_legal:
        signals.append({
            "type": "warn", "icon": "warn",
            "label": "Aucune mention légale détectée",
            "detail": "Le site ne contient pas de mentions légales ni de politique de confidentialité visibles.",
            "source": "python"
        })

    if original_url != final_url:
        orig_host = urlparse(original_url).netloc
        final_host = urlparse(final_url).netloc
        if orig_host != final_host:
            signals.append({
                "type": "danger", "icon": "x",
                "label": "Redirection vers un domaine différent",
                "detail": f"Le lien redirige de {orig_host} vers {final_host}. Technique courante de dissimulation.",
                "source": "python"
            })

    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else ""
    brand_names = ["paypal", "orange", "mtn", "wave", "amazon", "apple", "microsoft", "facebook", "google"]
    for brand in brand_names:
        if brand in title.lower():
            orig_host = urlparse(original_url).netloc.lower()
            if brand not in orig_host:
                signals.append({
                    "type": "danger", "icon": "x",
                    "label": f"Titre de page usurpe la marque \"{brand}\"",
                    "detail": f"Le titre affiche \"{title}\" mais le domaine n'appartient pas à {brand}. Phishing probable.",
                    "source": "python"
                })
                break

    return signals


class ScanRequest(BaseModel):
    url: str


@app.post("/scan")
async def scan(req: ScanRequest):
    raw_url = req.url.strip()
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    try:
        parsed = urlparse(raw_url)
    except Exception:
        return {"error": "URL invalide"}

    hostname = parsed.netloc.lower().split(":")[0]
    ext = tldextract.extract(raw_url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    tld = ext.suffix.split(".")[-1] if ext.suffix else ""
    full_url_lower = raw_url.lower()

    result = {
        "url": raw_url,
        "score": 0,
        "signals": [],
        "python_signals": [],
        "whois": {},
        "ssl": {},
        "content_analyzed": False,
    }

    trusted_match = next((d for d in TRUSTED_DOMAINS if hostname == d or hostname.endswith("." + d)), None)
    if trusted_match:
        result["signals"].append({
            "type": "safe", "icon": "check",
            "label": "Domaine de confiance reconnu",
            "detail": f"{trusted_match} est un domaine officiel vérifié.",
            "source": "python"
        })
        result["score"] = 0
        result["verdict"] = "Site fiable"
        result["level"] = "safe"
        return result

    for pattern in AFRICA_BLACKLIST:
        if pattern in full_url_lower:
            result["score"] += 50
            result["python_signals"].append({
                "type": "danger", "icon": "x",
                "label": "Arnaque africaine connue (base CI)",
                "detail": f'Pattern "{pattern}" référencé dans la base d\'arnaques Côte d\'Ivoire / Afrique.',
                "source": "python"
            })
            break

    brand, variant = check_typosquat(hostname)
    if brand:
        result["score"] += 40
        result["python_signals"].append({
            "type": "danger", "icon": "x",
            "label": f"Typosquatting — imitation de \"{brand}\"",
            "detail": f'"{variant}" imite la marque officielle "{brand}". Technique classique de phishing.',
            "source": "python"
        })

    if not raw_url.startswith("https://"):
        result["score"] += 25
        result["python_signals"].append({
            "type": "danger", "icon": "x",
            "label": "Connexion non sécurisée (HTTP)",
            "detail": "Le site n'utilise pas HTTPS. Vos données peuvent être interceptées.",
            "source": "python"
        })
    else:
        ssl_info = check_ssl(hostname)
        result["ssl"] = ssl_info
        if not ssl_info["valid"]:
            result["score"] += 20
            result["python_signals"].append({
                "type": "danger", "icon": "x",
                "label": "Certificat SSL invalide ou absent",
                "detail": f"Erreur SSL : {ssl_info.get('error', 'inconnu')}. Le site n'est pas sécurisé.",
                "source": "python"
            })
        elif ssl_info.get("days_left", 999) < 15:
            result["score"] += 10
            result["python_signals"].append({
                "type": "warn", "icon": "warn",
                "label": f"Certificat SSL expire dans {ssl_info['days_left']} jour(s)",
                "detail": "Un certificat expirant bientôt peut indiquer un site peu maintenu ou temporaire.",
                "source": "python"
            })
        else:
            result["python_signals"].append({
                "type": "safe", "icon": "check",
                "label": f"Certificat SSL valide ({ssl_info.get('days_left', '?')} jours restants)",
                "detail": "La connexion est chiffrée et le certificat est valide.",
                "source": "python"
            })

    free_hit = next((f for f in FREE_HOSTING if hostname.endswith(f) or f in hostname), None)
    if free_hit:
        result["score"] += 30
        result["python_signals"].append({
            "type": "danger", "icon": "x",
            "label": "Hébergement gratuit détecté",
            "detail": f'"{free_hit}" est un service d\'hébergement gratuit souvent utilisé pour des arnaques.',
            "source": "python"
        })

    if tld in RISKY_TLDS:
        result["score"] += 20
        result["python_signals"].append({
            "type": "danger", "icon": "x",
            "label": f"Extension de domaine risquée (.{tld})",
            "detail": f".{tld} est une extension souvent utilisée pour les arnaques car peu chère ou gratuite.",
            "source": "python"
        })

    if next((s for s in URL_SHORTENERS if hostname.endswith(s) or s in hostname), None):
        result["score"] += 30
        result["python_signals"].append({
            "type": "danger", "icon": "x",
            "label": "Lien raccourci — destination masquée",
            "detail": "Ce service masque la vraie destination du lien. Impossible de savoir où vous allez.",
            "source": "python"
        })

    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(hostname):
        result["score"] += 35
        result["python_signals"].append({
            "type": "danger", "icon": "x",
            "label": "Adresse IP directe utilisée",
            "detail": "Les sites légitimes n'utilisent pas d'adresses IP directes.",
            "source": "python"
        })

    parts = hostname.split(".")
    if len(parts) > 3:
        result["score"] += 15
        result["python_signals"].append({
            "type": "warn", "icon": "warn",
            "label": f"Sous-domaine complexe ({len(parts)-2} niveau(x))",
            "detail": "Plusieurs niveaux de sous-domaines sont une technique classique de phishing.",
            "source": "python"
        })

    url_for_kw = full_url_lower.replace("https://", "").replace("http://", "")
    kw_found = []
    for kw, score in SUSPICIOUS_KEYWORDS_URL:
        if kw in url_for_kw and kw not in [k[0] for k in kw_found]:
            result["score"] += score
            kw_found.append((kw, score))
    if kw_found:
        result["python_signals"].append({
            "type": "danger" if sum(s for _, s in kw_found) > 30 else "warn",
            "icon": "x" if sum(s for _, s in kw_found) > 30 else "warn",
            "label": f"{len(kw_found)} mot(s) suspect(s) dans l'URL",
            "detail": "Mots détectés : " + ", ".join(f'"{k}"' for k, _ in kw_found[:6]),
            "source": "python"
        })

    whois_info = await asyncio.to_thread(get_whois_info, domain)
    result["whois"] = whois_info
    if whois_info["found"] and whois_info.get("age_days") is not None:
        age = whois_info["age_days"]
        if age < 30:
            result["score"] += 35
            result["python_signals"].append({
                "type": "danger", "icon": "x",
                "label": f"Domaine très récent ({age} jour(s))",
                "detail": f"Créé le {whois_info.get('creation', '?')}. Les arnaques utilisent des domaines créés juste avant l'attaque.",
                "source": "python"
            })
        elif age < 180:
            result["score"] += 15
            result["python_signals"].append({
                "type": "warn", "icon": "warn",
                "label": f"Domaine récent ({age} jours)",
                "detail": f"Ce domaine a moins de 6 mois. Restez vigilant.",
                "source": "python"
            })
        else:
            result["python_signals"].append({
                "type": "safe", "icon": "check",
                "label": f"Domaine ancien ({age} jours)",
                "detail": f"Créé le {whois_info.get('creation', '?')} — chez {whois_info.get('registrar', '?')}. Bon indicateur.",
                "source": "python"
            })
    elif not whois_info["found"]:
        result["score"] += 10
        result["python_signals"].append({
            "type": "warn", "icon": "warn",
            "label": "Informations WHOIS introuvables",
            "detail": "Impossible de récupérer les données d'enregistrement du domaine.",
            "source": "python"
        })

    page = await fetch_page_content(raw_url)
    if page["ok"]:
        result["content_analyzed"] = True
        content_signals = analyze_html_content(page["html"], raw_url, page["final_url"])
        for sig in content_signals:
            if sig["type"] == "danger":
                result["score"] += 20
            elif sig["type"] == "warn":
                result["score"] += 8
        result["python_signals"].extend(content_signals)
    else:
        result["python_signals"].append({
            "type": "warn", "icon": "warn",
            "label": "Contenu de la page inaccessible",
            "detail": f"Impossible de charger la page : {page.get('error', 'erreur inconnue')}",
            "source": "python"
        })

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


@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0"}
