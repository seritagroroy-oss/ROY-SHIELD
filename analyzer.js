const SUSPICIOUS_DOMAINS = [
  "netlify.app", "github.io", "vercel.app", "glitch.me", "replit.dev",
  "weebly.com", "wix.com", "blogspot.com", "wordpress.com", "sites.google.com",
  "000webhostapp.com", "infinityfreeapp.com", "bsite.net", "freehostia.com",
  "x10host.com", "byethost", "freehosting", "hostfree", "ugu.pl",
  "tk", "ml", "ga", "cf", "gq", "buzz", "xyz"
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "adf.ly", "shorte.st", "bc.vc", "clk.sh", "rb.gy",
  "cutt.ly", "shorturl.at", "tiny.cc"
];

const SUSPICIOUS_KEYWORDS = [
  { word: "urgent", score: 15, label: "Urgence signalée dans l'URL" },
  { word: "urgence", score: 15, label: "Urgence signalée dans l'URL" },
  { word: "paiement", score: 12, label: "Référence à un paiement" },
  { word: "payment", score: 12, label: "Référence à un paiement" },
  { word: "pay", score: 8, label: "Référence à un paiement" },
  { word: "recrute", score: 12, label: "Recrutement suspect" },
  { word: "recrutement", score: 12, label: "Recrutement suspect" },
  { word: "emploi", score: 8, label: "Offre d'emploi suspecte" },
  { word: "job", score: 6, label: "Offre d'emploi dans l'URL" },
  { word: "frais", score: 15, label: "Frais demandés" },
  { word: "promo", score: 8, label: "Promotion suspecte" },
  { word: "promotion", score: 8, label: "Promotion suspecte" },
  { word: "gagner", score: 12, label: "Promesse de gain" },
  { word: "win", score: 10, label: "Promesse de gain" },
  { word: "winner", score: 10, label: "Promesse de gain" },
  { word: "gratuit", score: 8, label: "Offre gratuite suspecte" },
  { word: "free", score: 6, label: "Offre gratuite suspecte" },
  { word: "cadeau", score: 10, label: "Promesse de cadeau" },
  { word: "gift", score: 10, label: "Promesse de cadeau" },
  { word: "compte", score: 8, label: "Référence à un compte" },
  { word: "account", score: 8, label: "Référence à un compte" },
  { word: "verify", score: 12, label: "Demande de vérification" },
  { word: "verif", score: 12, label: "Demande de vérification" },
  { word: "confirm", score: 10, label: "Demande de confirmation" },
  { word: "update", score: 6, label: "Mise à jour suspecte" },
  { word: "secure", score: 6, label: "Fausse sécurisation" },
  { word: "login", score: 8, label: "Page de connexion suspecte" },
  { word: "password", score: 10, label: "Collecte de mot de passe" },
  { word: "bank", score: 12, label: "Référence bancaire" },
  { word: "banque", score: 12, label: "Référence bancaire" },
  { word: "mtn", score: 8, label: "Usurpation d'opérateur mobile" },
  { word: "orange", score: 6, label: "Possible usurpation d'opérateur" },
  { word: "moov", score: 8, label: "Usurpation d'opérateur mobile" },
  { word: "wave", score: 6, label: "Possible usurpation de Wave" },
  { word: "amazon", score: 12, label: "Usurpation d'Amazon" },
  { word: "paypal", score: 15, label: "Usurpation de PayPal" },
  { word: "apple", score: 10, label: "Possible usurpation d'Apple" },
  { word: "microsoft", score: 10, label: "Possible usurpation de Microsoft" },
  { word: "google", score: 6, label: "Référence à Google dans l'URL" }
];

const TRUSTED_DOMAINS = [
  "google.com", "youtube.com", "facebook.com", "instagram.com",
  "twitter.com", "x.com", "linkedin.com", "microsoft.com",
  "apple.com", "amazon.com", "netflix.com", "wikipedia.org",
  "github.com", "stackoverflow.com", "reddit.com", "paypal.com",
  "orange.com", "mtn.com", "ci.orange.com", "orange.ci",
  "wave.com", "moov.ci", "boa.ci", "bicici.ci", "sgbci.ci",
  "bceao.int", "gouv.ci", "impots.ci", "tresor.ci"
];

// #6 — Base locale africaine : domaines et patterns d'arnaques connues en CI et Afrique
const AFRICA_BLACKLIST = [
  { pattern: "mtn-ci-promo", label: "Faux concours MTN Côte d'Ivoire" },
  { pattern: "orange-money-ci", label: "Fausse page Orange Money CI" },
  { pattern: "wave-transfert", label: "Fausse page Wave CI" },
  { pattern: "recrutement-ci", label: "Faux recrutement Côte d'Ivoire" },
  { pattern: "emploi-abidjan", label: "Fausse offre d'emploi Abidjan" },
  { pattern: "bourse-etude-ci", label: "Fausse bourse d'études CI" },
  { pattern: "visa-ci", label: "Fausse procédure de visa CI" },
  { pattern: "concours-mtn", label: "Faux concours opérateur mobile" },
  { pattern: "concours-orange", label: "Faux concours opérateur mobile" },
  { pattern: "tresor-ci", label: "Usurpation du Trésor Public CI" },
  { pattern: "douane-ci", label: "Usurpation des Douanes CI" },
  { pattern: "cnps-ci", label: "Usurpation de la CNPS CI" },
  { pattern: "cie-ci", label: "Usurpation de la CIE CI" },
  { pattern: "sodeci", label: "Possible usurpation SODECI" },
  { pattern: "feec-ci", label: "Usurpation fédération sportive CI" },
  { pattern: "bourse-niger", label: "Fausse bourse Niger" },
  { pattern: "emploi-dakar", label: "Fausse offre emploi Sénégal" },
  { pattern: "emploi-mali", label: "Fausse offre emploi Mali" },
  { pattern: "recrutement-senegal", label: "Faux recrutement Sénégal" },
  { pattern: "moov-money", label: "Possible usurpation Moov Money" },
  { pattern: "airtel-money", label: "Possible usurpation Airtel Money" },
  { pattern: "momo-gratuit", label: "Faux gain mobile money" },
  { pattern: "carte-sim-gratuit", label: "Fausse offre SIM gratuite" },
  { pattern: "ivoirjob", label: "Faux site d'emploi ivoirien connu pour phishing" },
  { pattern: "ci-emploi", label: "Faux portail emploi CI" }
];

// #3 — Typosquatting : marques connues et leurs variantes légitimes
const BRAND_TYPOSQUAT = [
  { brand: "paypal", legit: "paypal.com", variants: ["paypa1", "pay-pal", "paypai", "paypall", "paypalci", "paypal-ci", "paypal-secure"] },
  { brand: "orange", legit: "orange.ci / orange.com", variants: ["0range", "orang3", "orange-ci-money", "orangemoney-ci", "orange-money"] },
  { brand: "mtn", legit: "mtn.com", variants: ["mtn-ci", "mtn-money", "mtnci", "m-t-n", "mtn2", "mtnpromo"] },
  { brand: "wave", legit: "wave.com", variants: ["waave", "wave-ci", "wave-money", "wavemoney", "wave-transfert"] },
  { brand: "amazon", legit: "amazon.com", variants: ["amaz0n", "amazzon", "amazon-promo", "amazon-ci", "amazonn"] },
  { brand: "google", legit: "google.com", variants: ["g00gle", "gooogle", "googIe", "google-ci", "googlesecure"] },
  { brand: "microsoft", legit: "microsoft.com", variants: ["micros0ft", "microsooft", "microsoft-secure", "micr0soft"] },
  { brand: "apple", legit: "apple.com", variants: ["appIe", "app1e", "apple-id-secure", "apple-verify"] },
  { brand: "facebook", legit: "facebook.com", variants: ["faceb00k", "facebok", "facebook-ci", "face-book"] },
  { brand: "instagram", legit: "instagram.com", variants: ["instagr4m", "instagran", "instagram-ci", "insta-gram"] },
  { brand: "whatsapp", legit: "whatsapp.com", variants: ["whatsap", "whatsapp-ci", "whatssapp", "whatsapp-promo"] },
  { brand: "linkedin", legit: "linkedin.com", variants: ["linkedln", "linke-din", "linkedin-job"] },
  { brand: "moov", legit: "moov.ci", variants: ["m00v", "moov-ci", "moov-money", "moovcash"] }
];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function detectTyposquat(hostname) {
  const domainCore = hostname.replace(/^www\./, "").split(".")[0].toLowerCase();
  for (const entry of BRAND_TYPOSQUAT) {
    for (const variant of entry.variants) {
      if (hostname.includes(variant)) {
        return { found: true, brand: entry.brand, legit: entry.legit, variant };
      }
    }
    if (domainCore !== entry.brand && levenshtein(domainCore, entry.brand) === 1 && domainCore.length > 3) {
      return { found: true, brand: entry.brand, legit: entry.legit, variant: domainCore };
    }
  }
  return { found: false };
}

function extractURLsFromText(text) {
  const regex = /https?:\/\/[^\s"'<>]+|www\.[^\s"'<>]+\.[a-z]{2,}[^\s"'<>]*/gi;
  const matches = text.match(regex) || [];
  return [...new Set(matches)];
}

function analyzeURL(rawUrl) {
  const result = {
    url: rawUrl,
    score: 0,
    signals: [],
    verdict: "",
    level: ""
  };

  let url = rawUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    result.score = 90;
    result.signals.push({
      type: "danger", icon: "x",
      label: "URL invalide",
      detail: "Ce lien n'est pas une URL valide."
    });
    result.verdict = "Lien invalide";
    result.level = "danger";
    return result;
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const fullUrl = url.toLowerCase();
  const pathname = parsedUrl.pathname.toLowerCase();

  const trustedBase = TRUSTED_DOMAINS.find(d => hostname === d || hostname.endsWith("." + d));
  if (trustedBase) {
    result.score = 0;
    result.signals.push({
      type: "safe", icon: "check",
      label: "Domaine de confiance reconnu",
      detail: `${trustedBase} est un domaine officiel vérifié.`
    });
    result.verdict = "Site fiable";
    result.level = "safe";
    return result;
  }

  // #6 — Vérification blacklist africaine
  const africaHit = AFRICA_BLACKLIST.find(e => fullUrl.includes(e.pattern));
  if (africaHit) {
    result.score += 50;
    result.signals.push({
      type: "danger", icon: "x",
      label: "Arnaque africaine connue détectée",
      detail: `Pattern reconnu : "${africaHit.pattern}" — ${africaHit.label}. Lien signalé dans notre base locale CI/Afrique.`
    });
  }

  // #3 — Typosquatting
  const typo = detectTyposquat(hostname);
  if (typo.found) {
    result.score += 40;
    result.signals.push({
      type: "danger", icon: "x",
      label: `Typosquatting détecté — imitation de "${typo.brand}"`,
      detail: `Le domaine "${typo.variant}" ressemble fortement à "${typo.legit}". C'est une technique classique pour tromper les utilisateurs.`
    });
  }

  if (!rawUrl.startsWith("https://")) {
    if (rawUrl.startsWith("http://")) {
      result.score += 25;
      result.signals.push({
        type: "danger", icon: "x",
        label: "Connexion non sécurisée (HTTP)",
        detail: "Le site n'utilise pas HTTPS. Vos données peuvent être interceptées."
      });
    }
  } else {
    result.signals.push({
      type: "safe", icon: "check",
      label: "Connexion chiffrée HTTPS",
      detail: "Le lien utilise HTTPS, ce qui est un bon signe."
    });
  }

  const isShortener = URL_SHORTENERS.find(s => hostname.includes(s));
  if (isShortener) {
    result.score += 30;
    result.signals.push({
      type: "danger", icon: "x",
      label: "Lien raccourci suspect",
      detail: `${hostname} est un service de raccourcissement. La vraie destination est masquée.`
    });
  }

  let freeDomainFound = false;
  for (const suspDomain of SUSPICIOUS_DOMAINS) {
    if (hostname.endsWith(suspDomain) || hostname.includes(suspDomain)) {
      const addScore = suspDomain.length <= 3 ? 25 : 30;
      result.score += addScore;
      result.signals.push({
        type: "danger", icon: "x",
        label: "Domaine gratuit ou risqué détecté",
        detail: `"${suspDomain}" est souvent utilisé pour des sites frauduleux car il est gratuit et anonyme.`
      });
      freeDomainFound = true;
      break;
    }
  }

  const subdomainParts = hostname.split(".");
  if (subdomainParts.length > 3) {
    result.score += 15;
    result.signals.push({
      type: "warn", icon: "warn",
      label: "Sous-domaine complexe suspect",
      detail: `L'URL contient ${subdomainParts.length - 2} niveau(x) de sous-domaine(s), ce qui est une technique courante de phishing.`
    });
  }

  const hasIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
  if (hasIP) {
    result.score += 35;
    result.signals.push({
      type: "danger", icon: "x",
      label: "Adresse IP au lieu d'un domaine",
      detail: "Les sites légitimes utilisent des noms de domaine, pas des adresses IP directes."
    });
  }

  const domainName = hostname.replace(/^www\./, "").split(".")[0];
  const hasNumbers = /\d/.test(domainName);
  const hasDashes = (domainName.match(/-/g) || []).length > 1;
  if (hasNumbers && hasDashes) {
    result.score += 15;
    result.signals.push({
      type: "warn", icon: "warn",
      label: "Nom de domaine suspect (chiffres + tirets)",
      detail: "La combinaison de chiffres et de tirets multiples est souvent signe d'un faux site."
    });
  }

  const urlForKeywords = fullUrl.replace(/https?:\/\//, "");
  const foundKeywords = [];
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (urlForKeywords.includes(kw.word)) {
      result.score += kw.score;
      if (!foundKeywords.find(f => f.label === kw.label)) {
        foundKeywords.push(kw);
      }
    }
  }

  if (foundKeywords.length > 0) {
    result.signals.push({
      type: foundKeywords.reduce((s, k) => s + k.score, 0) > 30 ? "danger" : "warn",
      icon: foundKeywords.reduce((s, k) => s + k.score, 0) > 30 ? "x" : "warn",
      label: `${foundKeywords.length} mot(s) suspect(s) dans l'URL`,
      detail: foundKeywords.map(k => `"${k.word}" — ${k.label}`).join("; ")
    });
  }

  const hasLongPath = pathname.length > 80;
  if (hasLongPath) {
    result.score += 10;
    result.signals.push({
      type: "warn", icon: "warn",
      label: "URL anormalement longue",
      detail: "Les arnaques utilisent souvent des URLs très longues pour cacher des paramètres malveillants."
    });
  }

  const hasQueryWithToken = parsedUrl.search.toLowerCase().includes("token") ||
    parsedUrl.search.toLowerCase().includes("session") ||
    parsedUrl.search.toLowerCase().includes("id=");
  if (hasQueryWithToken) {
    result.score += 10;
    result.signals.push({
      type: "warn", icon: "warn",
      label: "Paramètres de session dans l'URL",
      detail: "Des paramètres comme token, session ou id sont parfois utilisés pour du phishing ciblé."
    });
  }

  if (!africaHit && !typo.found && !freeDomainFound && !isShortener && !hasIP && foundKeywords.length === 0) {
    result.signals.push({
      type: "safe", icon: "check",
      label: "Aucune anomalie majeure détectée",
      detail: "Le domaine ne correspond à aucun pattern connu d'arnaque."
    });
  }

  result.score = Math.min(result.score, 100);

  if (result.score >= 60) {
    result.verdict = "Arnaque probable";
    result.level = "danger";
  } else if (result.score >= 30) {
    result.verdict = "Site suspect";
    result.level = "warn";
  } else {
    result.verdict = "Site fiable";
    result.level = "safe";
  }

  return result;
}
