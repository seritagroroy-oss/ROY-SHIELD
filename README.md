# ROY SHIELD

ROY SHIELD est un detecteur d'arnaques web avec une interface frontend moderne et une API Python pour analyser les liens suspects.

## Fonctionnalites

- Analyse de liens suspects
- Detection de signaux de phishing et de typosquatting
- Verification de contenu HTML et de formulaires
- Analyse WHOIS, SSL et redirections
- Interface web simple pour scanner des URLs ou du texte

## Fichiers principaux

- `index.html` : interface principale
- `style.css` : styles de l'application
- `app.js` : logique frontend
- `analyzer.js` : logique d'analyse cote client
- `backend.py` : API FastAPI
- `requirements.txt` : dependances Python

## Installation

### 1. Cloner le depot

```bash
git clone https://github.com/seritagroroy-oss/ROY-SHIELD.git
cd ROY-SHIELD
```

### 2. Creer un environnement virtuel

```bash
python -m venv .venv
```

Sous Windows PowerShell :

```powershell
.venv\Scripts\Activate.ps1
```

Sous macOS / Linux :

```bash
source .venv/bin/activate
```

### 3. Installer les dependances

```bash
pip install -r requirements.txt
```

## Lancer le backend

```bash
uvicorn backend:app --reload
```

Le serveur demarre par defaut sur `http://127.0.0.1:8000`.

## Ouvrir le frontend

Ouvrez `index.html` dans le navigateur.

Si le frontend doit appeler l'API localement, laissez le backend en cours d'execution pendant les tests.

## API

Documentation FastAPI automatique disponible ici une fois le serveur lance :

- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/redoc`

## Dependance principales

- FastAPI
- Uvicorn
- HTTPX
- BeautifulSoup
- python-whois
- tldextract

## Auteur

Projet publie sur GitHub : https://github.com/seritagroroy-oss/ROY-SHIELD
