(function () {
  "use strict";

  // ==========================================
  // CLAIRNET ENGINE 1.3.0
  // Détection locale des signaux suspects
  // ==========================================

  function normalize(value) {
    return String(value || "")
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "");
  }

  const RULES = [
    {
      id: "urgency",
      points: 14,
      title: "Pression ou urgence",
      detail: "Le message impose un délai ou cherche à provoquer une réaction précipitée.",
      pattern: /\b(urgent|immediatement|sans delai|dernier rappel|action requise|dans \d+ minutes?|expire aujourd'hui|suspendu|bloque|dans les prochaines minutes|aujourd'hui avant|sous 24 heures)\b/
    },
    {
      id: "credentials",
      points: 30,
      title: "Demande d'informations sensibles",
      detail: "Le message demande ou évoque des identifiants, mots de passe, codes ou données bancaires sensibles.",
      pattern: /\b(mots? de passe|identifiants?(?: bancaires?)?|identifiant de connexion|code sms|codes? de validation|codes? confidentiels?|coordonnees bancaires|numero de carte|cryptogramme|code secret|donnees bancaires|informations bancaires|acces a votre compte)\b/
    },
    {
      id: "identity",
      points: 10,
      title: "Demande de confirmation d'identité",
      detail: "Le message demande de confirmer ou de vérifier votre identité. Cette demande doit être contrôlée auprès de l'organisme officiel.",
      pattern: /\b(confirmez|confirmer|verifiez|verifier|validez|valider)\b.{0,80}\b(votre identite|votre compte|vos informations|vos donnees personnelles)\b|\b(confirmation|verification)\b.{0,60}\b(identite|compte bancaire|donnees personnelles)\b/
    },
    {
      id: "payment",
      points: 17,
      title: "Demande d'argent ou de paiement",
      detail: "Une demande de paiement ou de transfert inattendue mérite une vérification indépendante.",
      pattern: /\b(payer|paiement|reglez|regler|frais de livraison|remboursement|virement|amende|impaye|carte cadeau|pcs|transcash|neosurf|bitcoin|cryptomonnaie|crypto)\b/
    },
    {
      id: "link_action",
      points: 12,
      title: "Invitation à cliquer ou se connecter",
      detail: "Le message incite à utiliser un lien pour effectuer une action ou accéder à un compte.",
      pattern: /\b(cliquez ici|cliquer ici|cliquant sur le lien|cliquez sur le lien|cliquer sur le lien|en cliquant|suivez ce lien|lien ci-dessous|confirmez via|connectez-vous via|ouvrez le lien|rendez-vous sur le lien|consultez le lien|cliquez sur ce lien|cliquant sur ce lien|en cliquant sur ce lien)\b/
    },
    {
      id: "threat",
      points: 13,
      title: "Menace ou conséquence alarmante",
      detail: "Une menace ou une conséquence grave peut servir à vous faire agir rapidement.",
      pattern: /\b(poursuites judiciaires|fermeture definitive|dernier avertissement|saisie judiciaire|tribunal|condamnation|suspension definitive|blocage definitif|colis detruit|colis retourne a l'expediteur)\b/
    },
    {
      id: "phone",
      points: 18,
      title: "Demande de rappel suspecte",
      detail: "Le message demande de rappeler un prétendu service de sécurité ou un conseiller.",
      pattern: /\b(rappelez|rappeler|appelez|appeler)\b.{0,100}\b(service securite|service antifraude|centre d'opposition|conseiller bancaire|service bancaire)\b/
    },
    {
      id: "remote",
      points: 25,
      title: "Accès à distance potentiellement dangereux",
      detail: "Une demande d'installation d'un logiciel ou de communication d'un code d'accès à distance est présente.",
      pattern: /\b(anydesk|teamviewer|rustdesk)\b.{0,100}\b(code|identifiant|acces|installation|installer|communiquer|transmettre|partager)\b|\b(installez|installer|telechargez)\b.{0,100}\b(anydesk|teamviewer|rustdesk)\b/
    },
    {
      id: "gift",
      points: 22,
      title: "Moyen de paiement à risque",
      detail: "Les coupons prépayés et certaines demandes de cryptomonnaies sont utilisés dans des escroqueries.",
      pattern: /\b(coupons? pcs|tickets? transcash|codes? neosurf|cartes? cadeaux|bitcoin|cryptomonnaies?)\b/
    },

    // Détection spécifique aux livraisons
    {
      id: "delivery_context",
      points: 8,
      title: "Contexte de livraison ou de colis",
      detail: "Le message concerne un colis, un suivi ou une livraison. Ce contexte peut être utilisé dans des tentatives d'hameçonnage.",
      pattern: /\b(colis|livraison|livreur|transporteur|suivi de colis|numero de suivi|expedition|expediteur|destinataire|point relais|relais colis|retrait du colis|distribution du colis)\b/
    },
    {
      id: "delivery_fee",
      points: 18,
      title: "Frais de livraison ou de douane demandés",
      detail: "Une somme est réclamée pour débloquer, recevoir ou reprogrammer une livraison. Vérifiez cette demande directement auprès du transporteur.",
      pattern: /\b(frais de livraison|frais supplementaires|frais de douane|frais de dossier|frais de reexpedition|payer les frais|regler les frais|droits de douane|petit paiement pour recevoir|paiement pour debloquer|taxe de livraison|supplement de livraison)\b/
    },
    {
      id: "delivery_problem",
      points: 10,
      title: "Problème de livraison annoncé",
      detail: "Le message annonce un colis bloqué, retenu ou une livraison impossible. Vérifiez le suivi depuis le site officiel du transporteur.",
      pattern: /\b(colis bloque|colis retenu|colis en attente|livraison bloquee|livraison impossible|probleme de livraison|echec de livraison|adresse incomplete|adresse incorrecte|colis suspendu|colis non distribue|reprogrammer la livraison|reprogrammez votre livraison|nouvelle tentative de livraison)\b/
    },

    {
      id: "known_brand",
      points: 5,
      title: "Marque ou service connu mentionné",
      detail: "Les noms de marques peuvent être usurpés. Vérifiez l'expéditeur par un canal indépendant.",
      pattern: /\b(bnp paribas|credit agricole|societe generale|la banque postale|caisse d'epargne|banque populaire|boursobank|fortuneo|paypal|netflix|ameli|assurance maladie|impots|impots\.gouv\.fr|service public|service-public\.fr|la poste|colissimo|chronopost|mondial relay|relais colis|dhl|ups|fedex|amazon|apple|google|microsoft|orange|sfr|bouygues|free|caf)\b/
    }
  ];

  function extractLinks(text) {
    return text.match(
      /(?:https?:\/\/|www\.)[^\s<>"']+/gi
    ) || [];
  }

  function analyze(text) {
    const original = String(text || "").trim();

    if (!original) {
      throw new Error("Le message à analyser est vide.");
    }

    const normalized = normalize(original);
    const signals = [];
    let score = 5;

    RULES.forEach(function (rule) {
      if (rule.pattern.test(normalized)) {
        score += rule.points;

        signals.push({
          title: rule.title,
          detail: rule.detail
        });
      }
    });

    const links = extractLinks(original);

    if (links.length > 0) {
      score += 8;

      signals.push({
        title: "Adresse Internet présente",
        detail: "La présence d'un lien ne prouve pas une fraude. Son adresse et sa réputation doivent être vérifiées."
      });
    }

    if (/xn--/i.test(original)) {
      score += 15;

      signals.push({
        title: "Nom de domaine international à examiner",
        detail: "Certains domaines utilisent des caractères encodés pour imiter des adresses légitimes."
      });
    }

    if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(original)) {
      score += 12;

      signals.push({
        title: "Adresse IP présente",
        detail: "Une adresse IP directement utilisée dans un message mérite une vérification."
      });
    }

    const suspiciousEnding =
      /\.(example|invalid|test)(?:\b|\/|$)/i.test(original);

    if (suspiciousEnding) {
      score += 10;

      signals.push({
        title: "Domaine réservé de démonstration",
        detail: "Cette extension est réservée aux exemples et ne correspond pas à un site public ordinaire."
      });
    }

    score = Math.min(95, score);

    let level = "low";

    if (score >= 55) {
      level = "high";
    } else if (score >= 28) {
      level = "medium";
    }

    const labels = {
      low: "Peu de signaux repérés",
      medium: "Prudence recommandée",
      high: "Risque élevé suspecté"
    };

    const captions = {
      low: "Les règles de détection ont repéré peu d'indices.",
      medium: "Certains éléments méritent une vérification indépendante.",
      high: "Plusieurs indices d'alerte ressortent du message."
    };

    const advice = {
      low: "Restez vigilant. Un message peut être frauduleux même sans indice détecté.",
      medium: "Vérifiez l'expéditeur par un canal indépendant. Ne communiquez aucun code ni mot de passe.",
      high: "Ne cliquez pas et ne payez rien pour le moment. Contactez l'organisme par son application ou son site officiel."
    };

    if (signals.length === 0) {
      signals.push({
        title: "Aucun indice courant détecté",
        detail: "Cela ne garantit pas que le message est légitime. Cette analyse repose sur des règles locales."
      });
    }

    if (links.length > 0) {
      signals.push({
        title: "Lien non vérifié en ligne",
        detail: "Le moteur ne consulte pas encore de base de réputation et ne vérifie pas les redirections."
      });
    }

    return {
      text: original,
      score: score,
      level: level,
      label: labels[level],
      caption: captions[level],
      advice: advice[level],
      signals: signals,
      time: new Date()
    };
  }

  window.ClairnetEngine = Object.freeze({
    analyze: analyze,
    version: "1.3.0"
  });

})();
