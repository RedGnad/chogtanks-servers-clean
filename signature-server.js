const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
let helmet = null;
require('dotenv').config();

const app = express();
const crypto = require('crypto');
app.disable('x-powered-by');
// Render (proxy) – nécessaire pour que express-rate-limit lise X-Forwarded-For correctement
app.set('trust proxy', 1);
try {
    helmet = require('helmet');
    app.use(helmet());
} catch (_) {
    console.warn('[BOOT] helmet non installé - en-têtes sécurité non appliqués');
}
// Normalise les doubles slashs dans l'URL (Photon v1.2 peut envoyer //path)
app.use((req, res, next) => {
    if (req.url.includes('//')) {
        req.url = req.url.replace(/\/{2,}/g, '/');
    }
    next();
});
// CORS très tôt: refléter l'origine autorisée pour toutes les réponses (même erreurs)
const defaultAllowed = [
    'https://redgnad.github.io',
    'https://chogtanks.vercel.app',
    'https://monadclip.vercel.app'
];
const allowedFromEnv = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
const allowedOrigins = new Set(allowedFromEnv.length ? allowedFromEnv : defaultAllowed);
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.has(origin)) {
        res.set('Access-Control-Allow-Origin', origin);
        res.set('Vary', 'Origin');
        res.set('Access-Control-Allow-Credentials', 'true');
    }
    next();
});
// Parsers JSON dédiés par route (évite le coût global sur chaque requête)
const jsonParserSmall = express.json({ limit: '16kb' });
const jsonParserMedium = express.json({ limit: '64kb' });
// Masquer les détails d'erreur en prod si GENERIC_ERRORS=1
if (process.env.GENERIC_ERRORS === '1') {
    app.use((req, res, next) => {
        const originalJson = res.json.bind(res);
        res.json = (body) => {
            if (res.statusCode >= 400) {
                return originalJson({ error: 'Request rejected' });
            }
            return originalJson(body);
        };
        next();
    });
}
// Rate limit simple (optionnel via RATE_LIMIT_WINDOW_MS/RATE_LIMIT_MAX)
try {
    const rateLimit = require('express-rate-limit');
    const windowMs = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000); // 1 min
    const max = Number(process.env.RATE_LIMIT_MAX || 300); // 300 req/min par IP
    app.use(rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false, skip: (req) => req.method === 'OPTIONS' }));
} catch (_) {
    console.warn('[BOOT] express-rate-limit non installé - pas de rate limit');
}

// Helper pour créer des rate limiters route-spécifiques même si la lib est absente
function buildRouteLimiter(options) {
    try {
        const rateLimit = require('express-rate-limit');
        return rateLimit({
            standardHeaders: true,
            legacyHeaders: false,
            ...options
        });
    } catch (_) {
        return (req, res, next) => next();
    }
}
// HMAC par match (défense supplémentaire contre requêtes falsifiées)
const MATCH_SECRET = process.env.MATCH_SECRET || '';
function computeMatchSig(token, uid) {
    try {
        if (!MATCH_SECRET) return null;
        const h = crypto.createHmac('sha256', MATCH_SECRET);
        h.update(String(token || ''));
        h.update('|');
        h.update(String(uid || ''));
        return h.digest('hex');
    } catch (_) {
        return null;
    }
}

function computeScoreSig(token, uid, score) {
    try {
        if (!MATCH_SECRET) return null;
        const h = crypto.createHmac('sha256', MATCH_SECRET);
        h.update(String(token || ''));
        h.update('|');
        h.update(String(uid || ''));
        h.update('|');
        h.update(String(Number(score || 0)));
        return h.digest('hex');
    } catch (_) {
        return null;
    }
}

// Cap dynamique basé sur la durée du match (âge du matchToken)
function getDurationMaxScore(createdAtMs, defaultMax) {
    try {
        const enabled = process.env.ENABLE_DURATION_CAPS === '1';
        if (!enabled) return Number(defaultMax || 0);
        const now = Date.now();
        const age = (typeof createdAtMs === 'number') ? (now - createdAtMs) : 0;
        // Paliers par défaut: <30s => 10, <90s => 20, <179s => 40, sinon max statique
        const T1 = Number(process.env.CAP_TIER1_SECONDS || 30) * 1000;
        const T2 = Number(process.env.CAP_TIER2_SECONDS || 90) * 1000;
        const T3 = Number(process.env.CAP_TIER3_SECONDS || 179) * 1000;
        const C1 = Number(process.env.CAP_TIER1_MAX || 10);
        const C2 = Number(process.env.CAP_TIER2_MAX || 20);
        const C3 = Number(process.env.CAP_TIER3_MAX || 40);
        if (age < T1) return C1;
        if (age < T2) return C2;
        if (age < T3) return C3;
        return Number(defaultMax || 0);
    } catch (_) {
        return Number(defaultMax || 0);
    }
}

// Route-specific rate limiters (no-op if lib missing)
const matchStartLimiter = buildRouteLimiter({
    windowMs: Number(process.env.MATCH_START_WINDOW_MS || 60_000),
    max: Number(process.env.MATCH_START_MAX || 6)
});
const submitScoreLimiter = buildRouteLimiter({
    windowMs: Number(process.env.SUBMIT_SCORE_WINDOW_MS || 60_000),
    max: Number(process.env.SUBMIT_SCORE_MAX || 6)
});

app.use(cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, true); // allow non-browser tools
        if (allowedOrigins.has(origin)) return cb(null, true);
        return cb(new Error('Not allowed by CORS'));
    },
    credentials: true
}));

// Réponses rapides et cacheables aux preflights CORS
app.options('*', cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, true);
        if (allowedOrigins.has(origin)) return cb(null, true);
        return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'],
    allowedHeaders: ['Content-Type','Authorization','X-Match-Sig','X-Score-Sig'],
    maxAge: 600,
    optionsSuccessStatus: 204
}));

const port = process.env.PORT || 3001;

// Démarrage en mode dégradé si la clé n'est pas présente: ne pas quitter, garder /health up
let gameWallet = null;
if (!process.env.GAME_SERVER_PRIVATE_KEY) {
    console.error("ERREUR: GAME_SERVER_PRIVATE_KEY non définie. Les endpoints signés seront désactivés tant que la clé n'est pas configurée.");
} else {
    gameWallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY);
    console.log("Game Server Signer Address:", gameWallet.address);
}

// Middleware: exige la présence du wallet pour les routes nécessitant une signature/tx
function requireWallet(req, res, next) {
    if (!gameWallet) {
        return res.status(503).json({ error: 'Server wallet not configured' });
    }
    next();
}

// Middleware: exige et vérifie l'authentification Firebase (côté serveur)
function requireFirebaseAuth(req, res, next) {
    // Mode permissif si non activé explicitement
    if (process.env.FIREBASE_REQUIRE_AUTH !== '1') {
        return next();
    }

    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing token' });
    }
    const idToken = auth.slice(7);

    try {
        const admin = require('firebase-admin');
        if (!admin.apps.length) {
            const serviceAccount = {
                type: "service_account",
                project_id: process.env.FIREBASE_PROJECT_ID,
                private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
                private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
                client_email: process.env.FIREBASE_CLIENT_EMAIL,
                client_id: process.env.FIREBASE_CLIENT_ID,
                auth_uri: "https://accounts.google.com/o/oauth2/auth",
                token_uri: "https://oauth2.googleapis.com/token",
                auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
                client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
            };
            admin.initializeApp({
                credential: admin.credential.cert(serviceAccount),
                projectId: process.env.FIREBASE_PROJECT_ID
            });
        }

        admin.auth().verifyIdToken(idToken)
            .then((decoded) => {
                req.firebaseAuth = decoded; // uid, email, etc.
                return next();
            })
            .catch((err) => {
                console.error('[AUTH] verifyIdToken failed:', err.message || err);
                return res.status(401).json({ error: 'Invalid token' });
            });
    } catch (e) {
        console.error('[AUTH] Firebase admin init error:', e.message || e);
        return res.status(500).json({ error: 'Auth service unavailable' });
    }
}

// Health check endpoint pour monitoring
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
    version: '1.0.0',
    walletReady: Boolean(gameWallet)
    });
});
// Supporte aussi la méthode HEAD sur /health
app.head('/health', (req, res) => res.sendStatus(200));

// Proxy: check username (évite CORS côté WebView)
app.get('/api/check-username', async (req, res) => {
    try {
        const wallet = String(req.query.wallet || '').trim();
        if (!wallet || !/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
            return res.status(400).json({ error: 'Invalid wallet parameter' });
        }
        const fetch = require('node-fetch');
        const url = `https://monadclip.fun/api/check-wallet?wallet=${wallet}`;
        const r = await fetch(url, { method: 'GET', headers: { 'accept': 'application/json' } });
        const data = await r.json().catch(() => ({}));
        return res.status(r.ok ? 200 : 502).json(data);
    } catch (e) {
        console.error('[PROXY][check-username] Error:', e.message || e);
        return res.status(500).json({ error: 'Proxy failed' });
    }
});

// Root route simple pour éviter 502 sur GET /
app.get('/', (req, res) => {
    res.status(200).send('OK');
});

// Endpoint pour récupérer le score (compatibilité ancien build)
app.get('/api/firebase/get-score/:walletAddress', requireWallet, async (req, res) => {
    try {
        const { walletAddress } = req.params;
        if (!walletAddress || !/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
            return res.status(400).json({ error: 'Invalid wallet address format' });
        }
        
        const normalizedAddress = walletAddress.toLowerCase();
        
        // Essayer de récupérer depuis Firebase si configuré
        if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
            try {
                const admin = require('firebase-admin');
                if (!admin.apps.length) {
                    const serviceAccount = {
                        type: "service_account",
                        project_id: process.env.FIREBASE_PROJECT_ID,
                        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
                        private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
                        client_email: process.env.FIREBASE_CLIENT_EMAIL,
                        client_id: process.env.FIREBASE_CLIENT_ID,
                        auth_uri: "https://accounts.google.com/o/oauth2/auth",
                        token_uri: "https://oauth2.googleapis.com/token",
                        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
                        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
                    };
                    admin.initializeApp({
                        credential: admin.credential.cert(serviceAccount),
                        projectId: process.env.FIREBASE_PROJECT_ID
                    });
                }
                
                const db = admin.firestore();
                const docRef = db.collection('WalletScores').doc(normalizedAddress);
                const doc = await docRef.get();
                
                if (doc.exists) {
                    const data = doc.data();
                    const score = Number(data.score || 0);
                    const nftLevel = Number(data.nftLevel || 0);
                    console.log(`[GET-SCORE] Firebase data found: score=${score}, level=${nftLevel}`);
                    return res.json({ 
                        walletAddress: normalizedAddress, 
                        score: score, 
                        nftLevel: nftLevel, 
                        isNew: false 
                    });
                }
            } catch (firebaseError) {
                console.warn('[GET-SCORE] Firebase read failed:', firebaseError.message);
            }
        }
        
        // Fallback: valeurs par défaut si Firebase non configuré ou erreur
        console.log(`[GET-SCORE] Using fallback values for ${normalizedAddress}`);
        return res.json({ 
            walletAddress: normalizedAddress, 
            score: 0, 
            nftLevel: 0, 
            isNew: true 
        });
    } catch (error) {
        console.error('[GET-SCORE] Error:', error);
        res.status(500).json({ error: 'Failed to read score', details: error.message });
    }
});

// Endpoint pour démarrer un match (compatibilité ancien build)
// Match tokens in-memory (TTL court, anti-replay)
const matchTokens = new Map(); // token -> { uid, createdAt, expAt, used }

app.post('/api/match/start', jsonParserSmall, matchStartLimiter, requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        console.log(`[MATCH-START] Match start requested`);
        
        // Générer un token de match unique (cryptographiquement robuste)
        const matchToken = (require('crypto').randomBytes(16).toString('hex')) + Date.now().toString(36);
        const expiresInMs = Number(process.env.MATCH_TOKEN_TTL_MS || (2 * 60 * 1000)); // défaut 2 minutes
        const now = Date.now();
        const uid = req.firebaseAuth?.uid || null;
        // Optionnellement lier immédiatement à un gameId si fourni
        const providedGameId = typeof req.body?.gameId === 'string' ? req.body.gameId.trim() : null;
        const rec = {
            uid,
            createdAt: now,
            expAt: now + expiresInMs,
            used: false,
            gameId: providedGameId || null
        };
        // Calculer une signature serveur si MATCH_SECRET défini
        const sig = computeMatchSig(matchToken, uid);
        if (sig) rec.sig = sig;
        matchTokens.set(matchToken, rec);
        
        const tail = matchToken.slice(-6);
        console.log(`[MATCH-START] Generated match token: ****${tail}`);
        
        return res.json({
            matchToken: matchToken,
            expiresInMs: expiresInMs,
            matchSig: sig || null,
            success: true
        });
    } catch (error) {
        console.error('[MATCH-START] Error:', error);
        res.status(500).json({ error: 'Failed to start match', details: error.message });
    }
});

// Signature de score (anti "copy as fetch" sans Firebase delta)
app.post('/api/match/sign-score', jsonParserSmall, submitScoreLimiter, requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        if (!MATCH_SECRET) return res.status(503).json({ error: 'Score signing disabled' });
        const { matchToken, score, bonus } = req.body || {};
        if (!matchToken || typeof matchToken !== 'string') {
            return res.status(400).json({ error: 'Missing matchToken' });
        }
        const rec = matchTokens.get(matchToken);
        if (!rec) return res.status(401).json({ error: 'Invalid matchToken' });
        if (rec.expAt < Date.now()) {
            matchTokens.delete(matchToken);
            return res.status(401).json({ error: 'Match token expired' });
        }
        const uid = req.firebaseAuth?.uid || null;
        if (rec.uid && uid && rec.uid !== uid) {
            return res.status(401).json({ error: 'Match token does not belong to this user' });
        }
        // Aligner la signature sur la logique de soumission: (score + bonus) plafonné
        const MAX_SCORE_PER_MATCH = Number(process.env.MAX_SCORE_PER_MATCH || 50);
        const totalScore = (parseInt(score, 10) || 0) + (parseInt(bonus, 10) || 0);
        let cappedScore = Math.min(totalScore, MAX_SCORE_PER_MATCH);
        if (process.env.ENABLE_DURATION_CAPS === '1') {
            const dynMax = getDurationMaxScore(rec?.createdAt, MAX_SCORE_PER_MATCH);
            cappedScore = Math.min(cappedScore, dynMax);
        }
        const sig = computeScoreSig(matchToken, uid, Number(cappedScore));
        return res.json({ scoreSig: sig, cappedScore, success: true });
    } catch (e) {
        console.error('[MATCH][sign-score] error:', e.message || e);
        return res.status(500).json({ error: 'Failed to sign score' });
    }
});

// Endpoint pour soumettre les scores (compatibilité ancien build)
app.post('/api/firebase/submit-score', jsonParserMedium, submitScoreLimiter, requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const { walletAddress, score, bonus, matchId, matchToken, gameId } = req.body || {};
        if (!walletAddress || typeof score === 'undefined') {
            return res.status(400).json({ error: 'Missing walletAddress or score' });
        }
        if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
            return res.status(400).json({ error: 'Invalid wallet address format' });
        }

        const normalized = walletAddress.toLowerCase();
        const totalScore = (parseInt(score, 10) || 0) + (parseInt(bonus, 10) || 0);
        if (totalScore <= 0) {
            return res.status(204).end();
        }
        // Cap par match: sera calculé après lecture du matchToken (rec)
        let cappedScore = null; // calculé après validations du token

        // Enforce match token usage si auth active
        if (process.env.FIREBASE_REQUIRE_AUTH === '1') {
            if (!matchToken || typeof matchToken !== 'string') {
                return res.status(400).json({ error: 'Missing matchToken' });
            }
            const rec = matchTokens.get(matchToken);
            if (!rec) {
                return res.status(401).json({ error: 'Invalid matchToken' });
            }
            // Anti-match trop court
            const MIN_MATCH_DURATION_MS = Number(process.env.MIN_MATCH_DURATION_MS || 0);
            if (MIN_MATCH_DURATION_MS > 0) {
                const age = Date.now() - Number(rec.createdAt || 0);
                if (age < MIN_MATCH_DURATION_MS) {
                    return res.status(403).json({ error: 'Match too short' });
                }
            }
            if (rec.usedFirebase) {
                return res.status(401).json({ error: 'Match token already used' });
            }
            // HMAC check (si activé)
            if (MATCH_SECRET) {
                const providedSig = req.headers['x-match-sig'] || req.headers['x_match_sig'] || req.headers['x-matchsig'];
                const expected = computeMatchSig(matchToken, req.firebaseAuth?.uid || '');
                if (!providedSig || String(providedSig) !== expected) {
                    return res.status(401).json({ error: 'Invalid match signature' });
                }
            }
            if (rec.expAt < Date.now()) {
                matchTokens.delete(matchToken);
                return res.status(401).json({ error: 'Match token expired' });
            }
            const uid = req.firebaseAuth?.uid || null;
            if (rec.uid && uid && rec.uid !== uid) {
                return res.status(401).json({ error: 'Match token does not belong to this user' });
            }

            // Vérification Photon: l'utilisateur doit être présent (trace fraîche) dans la room
            let room = (typeof gameId === 'string' && gameId.trim())
              ? gameId.trim()
              : ((typeof matchId === 'string' && matchId.trim()) ? matchId.trim() : null);

            // Calcul de l'identifiant utilisateur pour la présence Photon
            let userKey = req.firebaseAuth?.uid || null;

            // Si matchId a la forme "<room>|<actorNr>", on en tire room + actorNr (prioritaire)
            if (typeof matchId === 'string' && matchId.includes('|')) {
              const parts = matchId.split('|');
              if (parts[0]) room = parts[0].trim();
              if (parts[1]) userKey = parts[1].trim();
            } else if (typeof matchId === 'string') {
              // Ancien format "match_<actorNr>_<timestamp>" : extraire actorNr
              const m = /^match_(\d+)_/.exec(matchId);
              if (m && m[1]) {
                userKey = m[1];
              }
            }

            // Mode strict: exiger un room explicite, pas de fallback global par actor
            const REQUIRE_EXPLICIT_ROOM = process.env.REQUIRE_EXPLICIT_ROOM === '1';
            const DISALLOW_ACTOR_ONLY = process.env.DISALLOW_ACTOR_ONLY === '1';
            if (!room) {
                if (REQUIRE_EXPLICIT_ROOM) {
                    return res.status(400).json({ error: 'Missing gameId (explicit room required)' });
                }
                const deduced = findRecentRoomForActor(userKey);
                if (deduced) room = deduced;
            }

            if (!room) {
                return res.status(400).json({ error: 'Missing gameId (Photon room)' });
            }

            // Vérrou tentative multi-submit (canal Firebase): refuser si déjà soumis côté Firebase
            if (room && userKey && hasRoomActorSubmitted(room, userKey)) {
                return res.status(409).json({ error: 'Score already submitted for this match' });
            }

            // Option: imposer que le score Privy corresponde au wallet vu côté Photon pour cet acteur
            const ENFORCE_PRIVY_FROM_PRESENCE = process.env.ENFORCE_WALLET_FROM_PRESENCE_PRIVY === '1';
            if (ENFORCE_PRIVY_FROM_PRESENCE) {
                try {
                    const sess = photonSessions[String(room)] || {};
                    const expected = sess.privyWallets ? sess.privyWallets[String(userKey)] : null;
                    if (expected && expected !== player) {
                        return res.status(403).json({ error: 'Privy wallet mismatch with Photon presence' });
                    }
                } catch (_) {}
            }

            // Option: imposer que le wallet AppKit soumis corresponde à celui observé via Photon pour cet acteur
            const ENFORCE_APPKIT_FROM_PRESENCE = process.env.ENFORCE_WALLET_FROM_PRESENCE_APPKIT === '1';
            if (ENFORCE_APPKIT_FROM_PRESENCE) {
                try {
                    const sess = photonSessions[String(room)] || {};
                    const expected = sess.wallets ? sess.wallets[String(userKey)] : null;
                    if (expected && expected !== normalized) {
                        return res.status(403).json({ error: 'Wallet mismatch with Photon presence' });
                    }
                } catch (_) {}
            }

            // Accepte si présence fraîche OU dans la fenêtre de grâce après fermeture
            if (!userKey || !hasAcceptablePhotonPresence(room, userKey)) {
                if (REQUIRE_EXPLICIT_ROOM) {
                    console.warn('[SUBMIT-SCORE][PHOTON-CHECK][STRICT] Reject explicit room presence: room=%s userKey=%s', room, userKey);
                    return res.status(403).json({ error: 'Photon presence not verified (explicit room required)' });
                }
                const altRoom = findRecentRoomForActor(userKey);
                if (!altRoom || !hasAcceptablePhotonPresence(altRoom, userKey)) {
                    console.warn('[SUBMIT-SCORE][PHOTON-CHECK] Reject: room=%s userKey=%s ttl=%d grace=%d', room, userKey, PHOTON_PRESENCE_TTL_MS, PHOTON_GRACE_AFTER_CLOSE_MS);
                    return res.status(403).json({ error: 'Photon presence not verified for this match' });
                }
                room = altRoom;
            }

            // Re-vérifier le verrou après fallback éventuel (canal Firebase)
            if (room && userKey && hasRoomActorSubmitted(room, userKey)) {
                return res.status(409).json({ error: 'Score already submitted for this match' });
            }

            // Lier le token au room final si non défini, sinon vérifier cohérence
            if (!rec.gameId && room) {
                rec.gameId = room;
            } else if (rec.gameId && room && rec.gameId !== room) {
                return res.status(401).json({ error: 'Match token not for this room' });
            }
            // Marquer l'utilisation Firebase seulement après validations de cohérence
            rec.usedFirebase = true;
            matchTokens.set(matchToken, rec);
            // Marquer le couple room|actor comme utilisé pour le canal Firebase (PAS Privy)
            if (room && userKey) markRoomActorSubmitted(room, userKey);
        }
        
        // Calcul du cap maintenant que rec est connu
        {
            const MAX_SCORE_PER_MATCH = Number(process.env.MAX_SCORE_PER_MATCH || 50);
            cappedScore = Math.min(totalScore, MAX_SCORE_PER_MATCH);
            if (process.env.ENABLE_DURATION_CAPS === '1') {
                const dynMax = getDurationMaxScore((typeof matchToken === 'string') ? (matchTokens.get(matchToken)?.createdAt) : undefined, MAX_SCORE_PER_MATCH);
                cappedScore = Math.min(cappedScore, dynMax);
            }
            if (cappedScore < totalScore) {
                console.log(`[SCORE-CAP] Score plafonné pour ${normalized}: ${totalScore} -> ${cappedScore} (MAX=${process.env.MAX_SCORE_PER_MATCH || 50})`);
            }
        }

        console.log(`[SUBMIT-SCORE] Score submitted for ${normalized}: total=${totalScore}, capped=${cappedScore} (base: ${score}, bonus: ${bonus})`);
        
        // Intégrer avec Firebase pour sauvegarder le score
        if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
            try {
                const admin = require('firebase-admin');
                if (!admin.apps.length) {
                    const serviceAccount = {
                        type: "service_account",
                        project_id: process.env.FIREBASE_PROJECT_ID,
                        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
                        private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
                        client_email: process.env.FIREBASE_CLIENT_EMAIL,
                        client_id: process.env.FIREBASE_CLIENT_ID,
                        auth_uri: "https://accounts.google.com/o/oauth2/auth",
                        token_uri: "https://oauth2.googleapis.com/token",
                        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
                        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
                    };
                    admin.initializeApp({
                        credential: admin.credential.cert(serviceAccount),
                        projectId: process.env.FIREBASE_PROJECT_ID
                    });
                }
                
                const db = admin.firestore();
                const docRef = db.collection('WalletScores').doc(normalized);
                
                // Récupérer le score actuel
                const doc = await docRef.get();
                let currentScore = 0;
                if (doc.exists) {
                    currentScore = Number(doc.data().score || 0);
                }
                
                // Ajouter le nouveau score (aligné sur cappedScore)
                const newTotalScore = currentScore + Number(cappedScore || 0);
                
                // Sauvegarder dans Firebase
                await docRef.set({
                    score: newTotalScore,
                    walletAddress: normalized,
                    lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
                    matchId: matchId || 'legacy'
                }, { merge: true });

                // Enregistrer le delta de match par uid pour validation Privy ultérieure
                try {
                    const uid = req.firebaseAuth?.uid;
                    if (uid) {
                        const stateRef = db.collection('UserMatchState').doc(String(uid));
                        await stateRef.set({
                            lastMatchId: matchId || null,
                            lastMatchToken: matchToken || null,
                            lastMatchDelta: Number(cappedScore || 0),
                            lastMatchSig: (matchToken && MATCH_SECRET) ? computeMatchSig(matchToken, uid) : null,
                            lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
                            usedByPrivy: false
                        }, { merge: true });
                    }
                } catch (e) {
                    console.warn('[MATCH-DELTA] failed to write UserMatchState:', e.message || e);
                }
                
                // Marquer le couple room|actor comme utilisé (idempotence per-match)
                try {
                    if (typeof matchId === 'string') {
                        let rm = null;
                        let actorKey = null;
                        if (matchId.includes('|')) {
                            const parts = matchId.split('|');
                            rm = parts[0] ? parts[0].trim() : null;
                            actorKey = parts[1] ? parts[1].trim() : null;
                        } else {
                            const m = /^match_(\d+)_/.exec(matchId);
                            if (m && m[1]) actorKey = m[1];
                        }
                        if (rm && actorKey) markRoomActorSubmitted(rm, actorKey);
                    }
                } catch (_) {}
                
                console.log(`[SUBMIT-SCORE] ✅ Score sauvegardé dans Firebase: ${currentScore} + ${totalScore} = ${newTotalScore}`);
                console.log(`[MONITORING] 📊 SCORE SUBMISSION - Wallet: ${normalized}, Score Added: ${totalScore}, New Total: ${newTotalScore}, Timestamp: ${new Date().toISOString()}`);
                
                return res.json({
                    success: true,
                    walletAddress: normalized,
                    score: newTotalScore,
                    matchId: matchId || 'legacy',
                    validated: true
                });
                
            } catch (firebaseError) {
                console.error('[SUBMIT-SCORE] Erreur Firebase:', firebaseError);
                // Strict: ne pas valider si la persistance échoue
                return res.status(500).json({
                    success: false,
                    error: 'Failed to persist score',
                    details: firebaseError.message || String(firebaseError)
                });
            }
        } else {
            console.warn('[SUBMIT-SCORE] Firebase non configuré - rejet strict en prod');
            return res.status(503).json({
                success: false,
                error: 'Score service unavailable',
                details: 'Firebase not configured'
            });
        }
    } catch (error) {
        console.error('[SUBMIT-SCORE] Error:', error);
        res.status(500).json({ error: 'Failed to submit score', details: error.message });
    }
});

app.post('/api/mint-authorization', requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const { playerAddress, mintCost, playerPoints } = req.body || {};
        const pAddr = playerAddress || req.body?.walletAddress; // alias compat

        if (!pAddr) {
            return res.status(400).json({ error: "Adresse du joueur requise" });
        }

        // Schéma robuste aligné contrat: (msg.sender, playerPoints, nonce, "MINT")
        if (typeof playerPoints !== 'undefined') {
            const nonce = Date.now();
            const message = ethers.utils.solidityKeccak256(
                ['address', 'uint256', 'uint256', 'string'],
                [pAddr, ethers.BigNumber.from(playerPoints), ethers.BigNumber.from(nonce), 'MINT']
            );
            const signature = await gameWallet.signMessage(ethers.utils.arrayify(message));

            console.log(`[MINT] ✅ Autorisation (nouveau schéma) pour ${pAddr}, points=${playerPoints}, nonce=${nonce}`);
            return res.json({
                authorized: true,
                signature,
                nonce,
                playerPoints: Number(playerPoints),
                gameServerAddress: gameWallet.address
            });
        }

        // Fallback legacy pour compat: (address, mintCost)
        if (typeof mintCost === 'undefined') {
            return res.status(400).json({ error: "Paramètre requis: playerPoints (recommandé) ou mintCost (legacy)" });
        }

        const messageLegacy = ethers.utils.solidityKeccak256(
            ['address', 'uint256'],
            [pAddr, ethers.BigNumber.from(mintCost)]
        );
        const signatureLegacy = await gameWallet.signMessage(ethers.utils.arrayify(messageLegacy));

        console.log(`[MINT] ✅ Autorisation (legacy) pour ${pAddr}, mintCost=${mintCost}`);
        return res.json({
            signature: signatureLegacy,
            mintCost: Number(mintCost),
            gameServerAddress: gameWallet.address
        });

    } catch (error) {
        console.error('Erreur d\'autorisation de mint:', error);
        res.status(500).json({ error: "Erreur interne du serveur" });
    }
});

// Endpoint PRIVY → Monad Games ID (submit-score, transactions=0)
app.post('/api/monad-games-id/submit-score', jsonParserSmall, submitScoreLimiter, requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const { privyAddress, score, bonus, matchId, matchToken, gameId } = req.body || {};
        if (!privyAddress || typeof score === 'undefined') {
            return res.status(400).json({ error: 'Missing privyAddress or score' });
        }
        if (!/^0x[a-fA-F0-9]{40}$/.test(privyAddress)) {
            return res.status(400).json({ error: 'Invalid privy address format' });
        }

        const player = String(privyAddress).toLowerCase();
        const totalScore = (parseInt(score, 10) || 0) + (parseInt(bonus, 10) || 0);
        const MAX_SCORE_PER_MATCH = Number(process.env.MAX_SCORE_PER_MATCH || 50);
        let cappedScore = Math.min(totalScore, MAX_SCORE_PER_MATCH);
        // Politique dure: si totalScore > MAX, annuler (0)
        if (totalScore > MAX_SCORE_PER_MATCH) {
            cappedScore = 0;
        }
        if (process.env.ENABLE_DURATION_CAPS === '1') {
            // on utilise rec.createdAt après sa récupération plus bas; ici on garde min statique
        }
        if (cappedScore <= 0) {
            return res.status(204).end();
        }

        // Enforce match token usage si auth active
        if (process.env.FIREBASE_REQUIRE_AUTH === '1') {
            if (!matchToken || typeof matchToken !== 'string') {
                return res.status(400).json({ error: 'Missing matchToken' });
            }
            const rec = matchTokens.get(matchToken);
            if (!rec) {
                return res.status(401).json({ error: 'Invalid matchToken' });
            }
            // Anti-match trop court
            const MIN_MATCH_DURATION_MS = Number(process.env.MIN_MATCH_DURATION_MS || 0);
            if (MIN_MATCH_DURATION_MS > 0) {
                const age = Date.now() - Number(rec.createdAt || 0);
                if (age < MIN_MATCH_DURATION_MS) {
                    return res.status(403).json({ error: 'Match too short' });
                }
            }
            // HMAC check (si activé)
            if (MATCH_SECRET) {
                const providedSig = req.headers['x-match-sig'] || req.headers['x_match_sig'] || req.headers['x-matchsig'];
                const expected = computeMatchSig(matchToken, req.firebaseAuth?.uid || '');
                if (!providedSig || String(providedSig) !== expected) {
                    return res.status(401).json({ error: 'Invalid match signature' });
                }
            }
            // Le token peut avoir été consommé par la route Firebase; on l'autorise si même room/actor
            if (rec.expAt < Date.now()) {
                matchTokens.delete(matchToken);
                return res.status(401).json({ error: 'Match token expired' });
            }
            let room = (typeof gameId === 'string' && gameId.trim())
              ? gameId.trim()
              : ((typeof matchId === 'string' && matchId.trim()) ? matchId.trim() : null);
            // Appliquer cap dynamique après avoir récupéré rec.createdAt
            if (process.env.ENABLE_DURATION_CAPS === '1') {
                const dynMax = getDurationMaxScore(rec?.createdAt, MAX_SCORE_PER_MATCH);
                cappedScore = Math.min(cappedScore, dynMax);
            }

            // Utiliser actorNr si fourni via matchId "room|actor"
            let userKey = req.firebaseAuth?.uid || null;
            if (typeof matchId === 'string' && matchId.includes('|')) {
                const parts = matchId.split('|');
                if (parts[0]) room = parts[0].trim();
                if (parts[1]) userKey = parts[1].trim();
            } else if (typeof matchId === 'string') {
                const m = /^match_(\d+)_/.exec(matchId);
                if (m && m[1]) userKey = m[1];
            }

            const REQUIRE_EXPLICIT_ROOM = process.env.REQUIRE_EXPLICIT_ROOM === '1';
            const DISALLOW_ACTOR_ONLY = process.env.DISALLOW_ACTOR_ONLY === '1';
            if (!room) {
                if (REQUIRE_EXPLICIT_ROOM) {
                    return res.status(400).json({ error: 'Missing gameId (explicit room required)' });
                }
                const deduced = findRecentRoomForActor(userKey);
                if (deduced) room = deduced;
            }
            if (!room) {
                return res.status(400).json({ error: 'Missing gameId (Photon room)' });
            }
            // Idempotence (canal Privy): refuser uniquement si Privy déjà soumis
            if (room && userKey && hasRoomActorPrivySubmitted(room, userKey)) {
                return res.status(409).json({ error: 'Privy score already submitted for this match' });
            }
            const BYPASS_PRIVY_PRESENCE = process.env.BYPASS_PRIVY_PRESENCE === '1';
            if (!BYPASS_PRIVY_PRESENCE && (!userKey || !hasAcceptablePhotonPresence(room, userKey))) {
                if (REQUIRE_EXPLICIT_ROOM) {
                    return res.status(403).json({ error: 'Photon presence not verified (explicit room required)' });
                }
                const altRoom = findRecentRoomForActor(userKey);
                if (!altRoom || !hasAcceptablePhotonPresence(altRoom, userKey)) {
                    // Fallback optionnel: accepter si X-Score-Sig valide même sans présence (fin de timer)
                    const ALLOW_PRIVY_WITHOUT_PRESENCE = process.env.ALLOW_PRIVY_WITHOUT_PRESENCE === '1';
                    if (ALLOW_PRIVY_WITHOUT_PRESENCE) {
                        const providedScoreSig = req.headers['x-score-sig'] || req.headers['x_score_sig'] || null;
                        const expectedScoreSig = computeScoreSig(matchToken, req.firebaseAuth?.uid || '', Number(cappedScore));
                        if (providedScoreSig && expectedScoreSig && providedScoreSig === expectedScoreSig) {
                            console.log('[PRIVY-FALLBACK] ✅ Accept without fresh presence (scoreSig ok)');
                        } else {
                            return res.status(403).json({ error: 'Photon presence not verified for this match' });
                        }
                    } else {
                        return res.status(403).json({ error: 'Photon presence not verified for this match' });
                    }
                }
                room = altRoom;
            } else if (BYPASS_PRIVY_PRESENCE) {
                // Mode contournement temporaire: exiger obligatoirement la signature de score
                const providedScoreSig = req.headers['x-score-sig'] || req.headers['x_score_sig'] || null;
                const expectedScoreSig = computeScoreSig(matchToken, req.firebaseAuth?.uid || '', Number(cappedScore));
                if (!providedScoreSig || providedScoreSig !== expectedScoreSig) {
                    return res.status(401).json({ error: 'Invalid score signature (presence bypass mode)' });
                }
                console.log('[PRIVY-BYPASS] ✅ Presence bypass with valid X-Score-Sig');
            }
            if (room && userKey && hasRoomActorPrivySubmitted(room, userKey)) {
                return res.status(409).json({ error: 'Privy score already submitted for this match' });
            }
            const recRoom = rec.gameId;
            if (!recRoom && room) {
                rec.gameId = room;
            } else if (recRoom && room && recRoom !== room) {
                return res.status(401).json({ error: 'Match token not for this room' });
            }
            if (DISALLOW_ACTOR_ONLY) {
                const isNumericActor = typeof userKey === 'string' && /^\d+$/.test(userKey);
                if (isNumericActor && (!req.firebaseAuth?.uid || String(req.firebaseAuth.uid).length < 10)) {
                    return res.status(401).json({ error: 'Actor-only user key not allowed in strict mode' });
                }
            }
            if (DISALLOW_ACTOR_ONLY) {
                const isNumericActor = typeof userKey === 'string' && /^\d+$/.test(userKey);
                if (isNumericActor && (!req.firebaseAuth?.uid || String(req.firebaseAuth.uid).length < 10)) {
                    return res.status(401).json({ error: 'Actor-only user key not allowed in strict mode' });
                }
            }
            // Ne pas durcir: si already usedFirebase, on n'écrase pas, sinon marquer usedPrivy
            if (!rec.usedFirebase) {
                rec.usedPrivy = true;
            }
            matchTokens.set(matchToken, rec);

            // Idempotence: marquer le couple room|actor comme utilisé pour le canal Privy
            try {
                if (room && userKey) {
                    markRoomActorPrivySubmitted(room, userKey);
                }
            } catch (_) {}

            // Option: exiger signature de score si activée
            if (process.env.REQUIRE_SCORE_SIG === '1') {
                const providedScoreSig = req.headers['x-score-sig'] || req.headers['x_score_sig'] || null;
                const expectedScoreSig = computeScoreSig(matchToken, req.firebaseAuth?.uid || '', Number(cappedScore));
                if (!providedScoreSig || providedScoreSig !== expectedScoreSig) {
                    return res.status(401).json({ error: 'Invalid score signature' });
                }
            }
        }

        // Si exigence stricte du delta: vérifier la cohérence avec Firebase
        const MANDATE_MATCH_DELTA = process.env.MANDATE_MATCH_DELTA === '1';
        if (MANDATE_MATCH_DELTA && process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
            try {
                const admin = require('firebase-admin');
                if (!admin.apps.length) {
                    const serviceAccount = {
                        type: "service_account",
                        project_id: process.env.FIREBASE_PROJECT_ID,
                        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
                        private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
                        client_email: process.env.FIREBASE_CLIENT_EMAIL,
                        client_id: process.env.FIREBASE_CLIENT_ID,
                        auth_uri: "https://accounts.google.com/o/oauth2/auth",
                        token_uri: "https://oauth2.googleapis.com/token",
                        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
                        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
                    };
                    admin.initializeApp({
                        credential: admin.credential.cert(serviceAccount),
                        projectId: process.env.FIREBASE_PROJECT_ID
                    });
                }
                const db = admin.firestore();
                const uid = req.firebaseAuth?.uid || null;
                if (uid) {
                    const stateRef = db.collection('UserMatchState').doc(String(uid));
                    const snap = await stateRef.get();
                    const st = snap.exists ? (snap.data() || {}) : {};
                    // Si l'état Firebase n'existe pas encore (soumission Privy-only), on n'échoue pas mais on s'appuie sur X-Score-Sig + présence Photon
                    const hasState = snap.exists && (st.lastMatchToken || st.lastMatchDelta !== undefined || st.lastMatchId || st.lastMatchSig);
                    if (hasState) {
                        // N'appliquer les contrôles que si la signature Firebase correspond à ce match
                        const expectedSig = (matchToken && MATCH_SECRET) ? computeMatchSig(matchToken, uid) : null;
                        const hasMatchingSig = Boolean(expectedSig && st.lastMatchSig && st.lastMatchSig === expectedSig);
                        if (hasMatchingSig) {
                            if (st.lastMatchToken && st.lastMatchToken !== matchToken) {
                                return res.status(409).json({ error: 'Mismatch match token' });
                            }
                            if (typeof matchId === 'string' && st.lastMatchId && st.lastMatchId !== matchId) {
                                return res.status(409).json({ error: 'Mismatch match id' });
                            }
                            if (st.lastMatchDelta !== undefined) {
                                const delta = Number(st.lastMatchDelta || 0);
                                if (delta !== Number(cappedScore)) {
                                    return res.status(409).json({ error: 'Score tamper detected' });
                                }
                            }
                            if (st.usedByPrivy === true) {
                                return res.status(409).json({ error: 'Match delta already consumed' });
                            }
                            await stateRef.set({ usedByPrivy: true }, { merge: true });
                        }
                        // Sinon: état Firebase ancien/non corrélé → on ne bloque pas, X-Score-Sig + présence couvrent la sécurité
                    }
                }
            } catch (e) {
                console.warn('[MATCH-DELTA][Privy] validation failed:', e.message || e);
                return res.status(503).json({ error: 'Match delta validation unavailable' });
            }
        }

        // Si batch activé: on queue le score avec tx=0
        if (ENABLE_MONAD_BATCH) {
            enqueuePlayerUpdate(player, cappedScore, 0, /*eventIds*/[]);
            return res.json({ success: true, queued: true, playerAddress: player, scoreAmount: cappedScore, transactionAmount: 0 });
        }

        // Sinon, on envoie en direct (tx=0) – ABI tuple
        const rpcUrl = process.env.MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz/';
        const provider = new ethers.providers.JsonRpcProvider(rpcUrl);
        const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
        const MONAD_GAMES_ID_CONTRACT = '0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0';
        const contractABI = [
            'function updatePlayerData((address player,uint256 score,uint256 transactions) data)'
        ];
        const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet);
        const dataTuple = { player, score: ethers.BigNumber.from(cappedScore), transactions: ethers.BigNumber.from(0) };

        // Préflight: callStatic + estimateGas
        try {
            await contract.callStatic.updatePlayerData(dataTuple);
        } catch (e) {
            return res.status(409).json({ error: 'Preflight failed', details: e.message || String(e) });
        }
        let gasLimit = ethers.BigNumber.from(150000);
        try {
            const est = await contract.estimateGas.updatePlayerData(dataTuple);
            gasLimit = est.mul(120).div(100); // +20%
        } catch (_) {}

        // Mutex simple
        while (serverTxMutex) { await new Promise(r => setTimeout(r, 50)); }
        serverTxMutex = true;
        const nonce = await getNextNonce(wallet);
        const tx = await contract.updatePlayerData(dataTuple, {
            gasLimit,
            maxPriorityFeePerGas: ethers.utils.parseUnits('2', 'gwei'),
            maxFeePerGas: ethers.utils.parseUnits('100', 'gwei'),
            nonce
        });
        console.log(`[Monad Games ID] submit-score tx: ${tx.hash} for ${player} +${cappedScore}`);
        // Ne pas attendre la confirmation ici
        return res.json({ success: true, transactionHash: tx.hash, playerAddress: player, scoreAmount: cappedScore, transactionAmount: 0 });
    } catch (error) {
        console.error('[Monad Games ID][submit-score] Error:', error);
        return res.status(500).json({ error: 'Failed to submit score to Monad Games ID', details: error.message });
    } finally {
        serverTxMutex = false;
    }
});

app.post('/api/evolve-authorization', requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const { playerAddress, tokenId, targetLevel, playerPoints } = req.body || {};

        if (!playerAddress || tokenId === undefined || targetLevel === undefined) {
            return res.status(400).json({ error: "Adresse du joueur, ID du token et niveau cible requis" });
        }

        const evolutionCosts = {
            2: 2,   // Level 1 -> 2
            3: 100, // Level 2 -> 3
            4: 200, // Level 3 -> 4
            5: 300, // Level 4 -> 5
            6: 400, // Level 5 -> 6
            7: 500, // Level 6 -> 7
            8: 600, // Level 7 -> 8
            9: 700, // Level 8 -> 9
            10: 800 // Level 9 -> 10
        };

        const requiredPoints = evolutionCosts[targetLevel];
        if (!requiredPoints) {
            return res.status(400).json({ error: "Niveau cible invalide" });
        }

        let pointsForSignature = Number(playerPoints ?? requiredPoints);

        // Option douce: vérifier le solde Firebase réel avant de signer (sans activer STRICT_POINTS)
        if (process.env.VERIFY_POINTS_BEFORE_SIGN === '1') {
            try {
                const admin = require('firebase-admin');
                if (!admin.apps.length) {
                    const serviceAccount = {
                        type: "service_account",
                        project_id: process.env.FIREBASE_PROJECT_ID,
                        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
                        private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
                        client_email: process.env.FIREBASE_CLIENT_EMAIL,
                        client_id: process.env.FIREBASE_CLIENT_ID,
                        auth_uri: "https://accounts.google.com/o/oauth2/auth",
                        token_uri: "https://oauth2.googleapis.com/token",
                        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
                        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
                    };
                    admin.initializeApp({
                        credential: admin.credential.cert(serviceAccount),
                        projectId: process.env.FIREBASE_PROJECT_ID
                    });
                }
                const db = admin.firestore();
                const normalized = String(playerAddress).toLowerCase();
                const docRef = db.collection('WalletScores').doc(normalized);
                const doc = await docRef.get();
                const serverScore = doc.exists ? Number(doc.data().score || 0) : 0;
                if (serverScore < requiredPoints) {
                    return res.status(403).json({ error: 'Insufficient points', required: requiredPoints, available: serverScore });
                }
                const clientPoints = Number(playerPoints ?? requiredPoints) || 0;
                if (clientPoints < requiredPoints) {
                    return res.status(403).json({ error: 'Client points below required', required: requiredPoints, provided: clientPoints });
                }
                if (clientPoints > serverScore) {
                    return res.status(403).json({ error: 'Client points exceed server score', provided: clientPoints, available: serverScore });
                }
                // Signe avec la valeur que le client utilisera on-chain, validée côté serveur
                pointsForSignature = clientPoints;
            } catch (firebaseError) {
                console.error('[EVOLVE-AUTH][VERIFY] Firebase error:', firebaseError.message || firebaseError);
                return res.status(500).json({ error: 'Failed to validate points' });
            }
        }

        if (STRICT_POINTS) {
            if (!(process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY)) {
                return res.status(503).json({ error: 'Score service unavailable for strict mode' });
            }
            try {
                const admin = require('firebase-admin');
                if (!admin.apps.length) {
                    const serviceAccount = {
                        type: "service_account",
                        project_id: process.env.FIREBASE_PROJECT_ID,
                        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
                        private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
                        client_email: process.env.FIREBASE_CLIENT_EMAIL,
                        client_id: process.env.FIREBASE_CLIENT_ID,
                        auth_uri: "https://accounts.google.com/o/oauth2/auth",
                        token_uri: "https://oauth2.googleapis.com/token",
                        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
                        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
                    };
                    admin.initializeApp({
                        credential: admin.credential.cert(serviceAccount),
                        projectId: process.env.FIREBASE_PROJECT_ID
                    });
                }
                const db = admin.firestore();
                const normalized = String(playerAddress).toLowerCase();
                const docRef = db.collection('WalletScores').doc(normalized);
                const doc = await docRef.get();
                const serverScore = doc.exists ? Number(doc.data().score || 0) : 0;
                if (serverScore < requiredPoints) {
                    return res.status(403).json({ error: 'Insufficient server points', required: requiredPoints, available: serverScore });
                }
                pointsForSignature = serverScore;
            } catch (firebaseError) {
                console.error('[EVOLVE-AUTH][STRICT] Firebase error:', firebaseError.message || firebaseError);
                return res.status(500).json({ error: 'Failed to validate server points' });
            }
        }
        const nonce = Date.now();

        // Doit correspondre EXACTEMENT au contrat ChogTanks.sol:
        // keccak256(abi.encodePacked(msg.sender, tokenId, targetLevel, playerPoints, nonce, "EVOLVE"))
        const message = ethers.utils.solidityKeccak256(
            ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'string'],
            [playerAddress, tokenId, targetLevel, pointsForSignature, nonce, 'EVOLVE']
        );
        const signature = await gameWallet.signMessage(ethers.utils.arrayify(message));

        console.log(`[EVOLVE] ✅ Autorisation d'évolution générée pour ${playerAddress}, token ${tokenId} → niveau ${targetLevel}`);
        console.log(`[MONITORING] 🚀 EVOLVE REQUEST - Wallet: ${playerAddress}, Token: ${tokenId}, Target Level: ${targetLevel}, Cost: ${requiredPoints}, PlayerPointsSigned: ${pointsForSignature}, Nonce: ${nonce}`);

        return res.json({
            authorized: true,
            signature,
            evolutionCost: requiredPoints,
            targetLevel,
            nonce,
            playerPointsSigned: Number(pointsForSignature)
        });

    } catch (error) {
        console.error('Evolve authorization error:', error);
        return res.status(500).json({ error: "Internal server error" });
    }
});

// Anti-farming: Stockage persistant des liaisons wallet
const fs = require('fs');
const path = require('path');

// Répertoire de stockage persistant (Render Persistent Disk)
const DATA_DIR = process.env.DATA_DIR || __dirname;
try {
    if (DATA_DIR !== __dirname && !fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }
} catch (e) {
    console.error('[STORAGE] Failed to ensure DATA_DIR:', e.message || e);
}

const WALLET_BINDINGS_FILE = path.join(DATA_DIR, 'wallet-bindings.json');

// Charger les liaisons existantes
function loadWalletBindings() {
    try {
        if (fs.existsSync(WALLET_BINDINGS_FILE)) {
            const data = fs.readFileSync(WALLET_BINDINGS_FILE, 'utf8');
            return new Map(Object.entries(JSON.parse(data)));
        }
    } catch (error) {
        console.error('[ANTI-FARMING] Erreur lecture fichier liaisons:', error.message);
    }
    return new Map();
}

// Sauvegarder les liaisons
function saveWalletBindings(bindings) {
    try {
        const data = JSON.stringify(Object.fromEntries(bindings), null, 2);
        fs.writeFileSync(WALLET_BINDINGS_FILE, data, 'utf8');
    } catch (error) {
        console.error('[ANTI-FARMING] Erreur sauvegarde fichier liaisons:', error.message);
    }
}

const walletBindings = loadWalletBindings();
console.log(`[ANTI-FARMING] ${walletBindings.size} liaisons chargées depuis ${WALLET_BINDINGS_FILE}`);

// =====================
// Verrou 1 soumission par room|actor (persistant) – canal Firebase
// =====================
const ROOM_ACTOR_USAGE_FILE = path.join(DATA_DIR, 'room-actor-usage.json');
function loadRoomActorUsage() {
    try {
        if (fs.existsSync(ROOM_ACTOR_USAGE_FILE)) {
            const raw = fs.readFileSync(ROOM_ACTOR_USAGE_FILE, 'utf8');
            const obj = JSON.parse(raw);
            if (obj && typeof obj === 'object') return obj;
        }
    } catch (e) {
        console.warn('[ROOM-ACTOR] load error:', e.message || e);
    }
    return {};
}
function saveRoomActorUsage(state) {
    try {
        fs.writeFileSync(ROOM_ACTOR_USAGE_FILE, JSON.stringify(state, null, 2), 'utf8');
    } catch (e) {
        console.warn('[ROOM-ACTOR] save error:', e.message || e);
    }
}
const roomActorUsed = loadRoomActorUsage(); // { "room|actor": timestamp }
function hasRoomActorSubmitted(room, actor) {
    if (!room || !actor) return false;
    const key = `${String(room)}|${String(actor)}`;
    const ts = roomActorUsed[key];
    if (!ts) return false;
    // TTL nettoyage doux (30 minutes)
    const TTL = Number(process.env.ROOM_ACTOR_USED_TTL_MS || 30 * 60 * 1000);
    if (Date.now() - Number(ts) > TTL) {
        delete roomActorUsed[key];
        saveRoomActorUsage(roomActorUsed);
        return false;
    }
    return true;
}
function markRoomActorSubmitted(room, actor) {
    if (!room || !actor) return;
    const key = `${String(room)}|${String(actor)}`;
    roomActorUsed[key] = Date.now();
    saveRoomActorUsage(roomActorUsed);
}

// =====================
// Verrou 1 soumission par room|actor (persistant) – canal Privy
// =====================
const ROOM_ACTOR_PRIVY_USAGE_FILE = path.join(DATA_DIR, 'room-actor-privy-usage.json');
function loadRoomActorPrivyUsage() {
    try {
        if (fs.existsSync(ROOM_ACTOR_PRIVY_USAGE_FILE)) {
            const raw = fs.readFileSync(ROOM_ACTOR_PRIVY_USAGE_FILE, 'utf8');
            const obj = JSON.parse(raw);
            if (obj && typeof obj === 'object') return obj;
        }
    } catch (e) {
        console.warn('[ROOM-ACTOR-PRIVY] load error:', e.message || e);
    }
    return {};
}
function saveRoomActorPrivyUsage(state) {
    try {
        fs.writeFileSync(ROOM_ACTOR_PRIVY_USAGE_FILE, JSON.stringify(state, null, 2), 'utf8');
    } catch (e) {
        console.warn('[ROOM-ACTOR-PRIVY] save error:', e.message || e);
    }
}
const roomActorPrivyUsed = loadRoomActorPrivyUsage(); // { "room|actor": timestamp }
function hasRoomActorPrivySubmitted(room, actor) {
    if (!room || !actor) return false;
    const key = `${String(room)}|${String(actor)}`;
    const ts = roomActorPrivyUsed[key];
    if (!ts) return false;
    const TTL = Number(process.env.ROOM_ACTOR_USED_TTL_MS || 30 * 60 * 1000);
    if (Date.now() - Number(ts) > TTL) {
        delete roomActorPrivyUsed[key];
        saveRoomActorPrivyUsage(roomActorPrivyUsed);
        return false;
    }
    return true;
}
function markRoomActorPrivySubmitted(room, actor) {
    if (!room || !actor) return;
    const key = `${String(room)}|${String(actor)}`;
    roomActorPrivyUsed[key] = Date.now();
    saveRoomActorPrivyUsage(roomActorPrivyUsed);
}

// =====================
// Idempotence événements traités (anti-replay)
// =====================
const PROCESSED_EVENTS_FILE = path.join(DATA_DIR, 'processed-events.json');
function loadProcessedEvents() {
    try {
        if (fs.existsSync(PROCESSED_EVENTS_FILE)) {
            const raw = fs.readFileSync(PROCESSED_EVENTS_FILE, 'utf8');
            const arr = JSON.parse(raw);
            if (Array.isArray(arr)) return new Set(arr);
        }
    } catch (e) {
        console.error('[IDEMPOTENCE] Erreur lecture processed events:', e.message || e);
    }
    return new Set();
}
function saveProcessedEvents(set) {
    try {
        const arr = Array.from(set);
        fs.writeFileSync(PROCESSED_EVENTS_FILE, JSON.stringify(arr, null, 2), 'utf8');
    } catch (e) {
        console.error('[IDEMPOTENCE] Erreur sauvegarde processed events:', e.message || e);
    }
}
const processedEvents = loadProcessedEvents();

// Idempotence renforcee: tracker les evenements et tx en cours
const processingEvents = new Set();
const processingTxHashes = new Set();
function isEventProcessedOrQueued(eventId) {
    return processedEvents.has(eventId) || processingEvents.has(eventId);
}

// =====================
// Débits de points (après confirmation on-chain)
// =====================
const POINTS_DEBIT_EVENTS_FILE = path.join(DATA_DIR, 'points-debited-events.json');
function loadPointsDebitedEvents() {
    try {
        if (fs.existsSync(POINTS_DEBIT_EVENTS_FILE)) {
            const raw = fs.readFileSync(POINTS_DEBIT_EVENTS_FILE, 'utf8');
            const arr = JSON.parse(raw);
            if (Array.isArray(arr)) return new Set(arr);
        }
    } catch (e) {
        console.error('[POINTS-DEBIT] Erreur lecture points debited events:', e.message || e);
    }
    return new Set();
}
function savePointsDebitedEvents(set) {
    try {
        const arr = Array.from(set);
        fs.writeFileSync(POINTS_DEBIT_EVENTS_FILE, JSON.stringify(arr, null, 2), 'utf8');
    } catch (e) {
        console.error('[POINTS-DEBIT] Erreur sauvegarde points debited events:', e.message || e);
    }
}
const pointsDebitedEvents = loadPointsDebitedEvents();

// =====================
// Photon presence (anti-script farm via HTTP)
// =====================
const PHOTON_WEBHOOK_SECRET = process.env.PHOTON_WEBHOOK_SECRET || '';
const PHOTON_PRESENCE_TTL_MS = Number(process.env.PHOTON_PRESENCE_TTL_MS || 60_000);
const PHOTON_GRACE_AFTER_CLOSE_MS = Number(process.env.PHOTON_GRACE_AFTER_CLOSE_MS || 300_000);
const PHOTON_SESSIONS_FILE = path.join(DATA_DIR, 'photon-sessions.json');

function loadPhotonSessions() {
    try {
        if (fs.existsSync(PHOTON_SESSIONS_FILE)) {
            return JSON.parse(fs.readFileSync(PHOTON_SESSIONS_FILE, 'utf8'));
        }
    } catch (e) {
        console.warn('[PHOTON] load error:', e.message || e);
    }
    return {};
}

function savePhotonSessions(state) {
    try {
        fs.writeFileSync(PHOTON_SESSIONS_FILE, JSON.stringify(state, null, 2), 'utf8');
    } catch (e) {
        console.warn('[PHOTON] save error:', e.message || e);
    }
}

// Structure: { [gameId]: { users: { [userId]: { lastSeen:number } }, wallets: { [actorOrUser]: address }, createdAt:number, closed:boolean, closedAt:number|null } }
const photonSessions = loadPhotonSessions();

// Helper: verify a fresh presence for a user in a Photon room
function hasFreshPhotonPresence(gameId, userId) {
    try {
        if (!gameId || !userId) return false;
        const sess = photonSessions[String(gameId)];
        if (!sess || !sess.users) return false;
        const u = sess.users[String(userId)];
        if (!u || typeof u.lastSeen !== 'number') return false;
        return (Date.now() - u.lastSeen) <= PHOTON_PRESENCE_TTL_MS;
    } catch (_) {
        return false;
    }
}

// Presence acceptable: soit fraîche, soit dans une fenêtre de grâce après fermeture/quit
function hasAcceptablePhotonPresence(gameId, userId) {
    try {
        if (!gameId || !userId) return false;
        const now = Date.now();
        const sess = photonSessions[String(gameId)];
        if (!sess || !sess.users) return false;
        const u = sess.users[String(userId)];
        if (!u || typeof u.lastSeen !== 'number') return false;
        const age = now - u.lastSeen;
        if (age <= PHOTON_PRESENCE_TTL_MS) return true;
        if (sess.closed && typeof sess.closedAt === 'number') {
            const sinceClose = now - sess.closedAt;
            if (sinceClose <= PHOTON_GRACE_AFTER_CLOSE_MS && age <= PHOTON_GRACE_AFTER_CLOSE_MS) {
                return true;
            }
        }
        return false;
    } catch (_) {
        return false;
    }
}

// Cherche la room la plus récente où cet utilisateur a été vu récemment
function findRecentRoomForActor(userId) {
    try {
        if (!userId) return null;
        const now = Date.now();
        let bestRoom = null;
        let bestLastSeen = 0;
        for (const [gid, sess] of Object.entries(photonSessions || {})) {
            const u = sess && sess.users ? sess.users[String(userId)] : null;
            if (!u || typeof u.lastSeen !== 'number') continue;
            const age = now - u.lastSeen;
            const withinPresence = age <= PHOTON_PRESENCE_TTL_MS;
            const withinGrace = sess && sess.closed && typeof sess.closedAt === 'number'
                ? (now - sess.closedAt) <= PHOTON_GRACE_AFTER_CLOSE_MS
                : false;
            if (withinPresence || withinGrace) {
                if (u.lastSeen > bestLastSeen) {
                    bestLastSeen = u.lastSeen;
                    bestRoom = gid;
                }
            }
        }
        return bestRoom;
    } catch (_) {
        return null;
    }
}

// Webhook endpoint to receive Photon Realtime callbacks (Create/Join/Leave/Close/Event)
app.post('/photon/webhook', jsonParserSmall, (req, res) => {
    try {
        if (PHOTON_WEBHOOK_SECRET) {
            const q = req.query || {};
            // Refuser tout secret passé en query pour éviter fuites URL
            if (q.secret) {
                return res.status(401).json({ error: 'Unauthorized (query secret not allowed)' });
            }
            let providedSecret = req.headers['x-webhook-secret'] || req.headers['x-photon-secret'];
            if (typeof providedSecret === 'string') {
                providedSecret = providedSecret.trim().replace(/[?#&]+$/g, '');
            }
            if (providedSecret !== PHOTON_WEBHOOK_SECRET) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
        }

        const body = req.body || {};
        // Support Photon v1.2 and v2 field names + normalize property events
        let type = String(body.Type || body.type || body.eventType || '').toLowerCase();
        // Normaliser les alias d'événements de propriétés vers 'gameproperties'
        if (['propertieschanged', 'roomproperties', 'propertyupdate', 'customproperties'].includes(type)) {
            type = 'gameproperties';
        }
        const gameId = String(body.GameId || body.gameId || body.roomName || body.room || '').trim();
        const userId = String(body.UserId || body.userId || '').trim();
        const actorKey = String(body.ActorNr || body.actorNr || body.ActorNumber || body.actorNumber || '').trim();
        const now = Date.now();

        if (!gameId) return res.status(400).json({ error: 'Missing GameId' });

        const sess = photonSessions[gameId] || { users: {}, wallets: {}, privyWallets: {}, createdAt: now, closed: false };
        console.log(`[PHOTON][WEBHOOK] type=${type} gameId=${gameId} userId=${userId} actor=${actorKey}`);
        switch (type) {
            case 'create':
            case 'gamecreated':
            case 'roomcreated':
            case 'gamestarted':
                sess.createdAt = now;
                // Marquer présence immédiatement si des identifiants sont fournis
                if (userId) { sess.users[userId] = { lastSeen: now }; }
                if (actorKey) { sess.users[actorKey] = { lastSeen: now }; }
                break;
            case 'join':
            case 'actorjoin':
            case 'playerjoined':
            case 'joinrequest':
                if (userId) { sess.users[userId] = { lastSeen: now }; }
                if (actorKey) { sess.users[actorKey] = { lastSeen: now }; }
                break;
            case 'leave':
            case 'actorleave':
            case 'playerleft':
            case 'leaverequest':
                if (userId) { sess.users[userId] = { lastSeen: now }; }
                if (actorKey) { sess.users[actorKey] = { lastSeen: now }; }
                break;
            case 'close':
            case 'gameclosed':
            case 'roomclosed':
                sess.closed = true;
                sess.closedAt = now;
                break;
            case 'event': {
                const data = body.Data || body.data || {};
                const uidFromData = String(data.userId || '').trim();
                const effectiveUser = userId || uidFromData;
                if (effectiveUser) { sess.users[effectiveUser] = { lastSeen: now }; }
                if (actorKey) { sess.users[actorKey] = { lastSeen: now }; }
                // Capture éventuelle des wallets (AppKit et Privy) envoyés dans l'event
                try {
                    const maybeAppKitWallet = String(data.wallet || data.appKitWallet || '').trim().toLowerCase();
                    const maybePrivyWallet = String(data.privyWallet || '').trim().toLowerCase();
                    const key = actorKey || effectiveUser;
                    if (key) {
                        // Stocker AppKit wallet si valide
                        if (/^0x[a-f0-9]{40}$/.test(maybeAppKitWallet)) {
                            sess.wallets[key] = maybeAppKitWallet;
                        }
                        // Stocker Privy wallet séparément si valide
                        if (/^0x[a-f0-9]{40}$/.test(maybePrivyWallet)) {
                            if (!sess.privyWallets) sess.privyWallets = {};
                            sess.privyWallets[key] = maybePrivyWallet;
                            console.log(`[PHOTON][WEBHOOK][EVENT] Stored Privy wallet for ${key}: ${maybePrivyWallet}`);
                        }
                    }
                } catch (_) {}
                break;
            }
            case 'gameproperties':
                if (userId) { sess.users[userId] = { lastSeen: now }; }
                if (actorKey) { sess.users[actorKey] = { lastSeen: now }; }
                try {
                    // Lire Properties (room custom properties) ET Data (fallback)
                    const props = body.Properties || body.properties || body.Data || body.data || {};
                    const maybePrivyWallet = String(props.privyWallet || '').trim().toLowerCase();
                    if (/^0x[a-f0-9]{40}$/.test(maybePrivyWallet)) {
                        if (!sess.privyWallets) sess.privyWallets = {};
                        const key = actorKey || userId;
                        if (key) {
                            sess.privyWallets[key] = maybePrivyWallet;
                            console.log(`[PHOTON][WEBHOOK][GAMEPROPS] Stored Privy wallet for ${key}: ${maybePrivyWallet}`);
                        }
                    }
                } catch (_) {}
                break;
            default:
                if (userId || actorKey) {
                    if (userId) { sess.users[userId] = { lastSeen: now }; }
                    if (actorKey) { sess.users[actorKey] = { lastSeen: now }; }
                } else {
                    console.log(`[PHOTON][WEBHOOK] Unknown event type: ${type}`);
                }
                break;
        }

        photonSessions[gameId] = sess;
        savePhotonSessions(photonSessions);
        return res.json({ ok: true });
    } catch (e) {
        console.error('[PHOTON][WEBHOOK] error:', e.message || e);
        return res.status(500).json({ error: 'Webhook error' });
    }
});

// =====================
// Monad Games ID - BATCH
// =====================
const ENABLE_MONAD_BATCH = process.env.ENABLE_MONAD_BATCH === '1';
const STRICT_POINTS = process.env.STRICT_POINTS === '1';
const BATCH_FLUSH_MS = Number(process.env.BATCH_FLUSH_MS || 1500); // 1.5s
const BATCH_MAX = Number(process.env.BATCH_MAX || 100);
const BATCH_MAX_WAIT_MS = Number(process.env.BATCH_MAX_WAIT_MS || 3000);

// Queue en mémoire: agrégation par joueur
// Structure: Map<address, { score: number, tx: number, debit: number, firstAt: number, eventIds: Set<string> }>
const batchQueue = new Map();
let isFlushing = false;
let lastFlushAt = Date.now();

function enqueuePlayerUpdate(player, scoreDelta, txDelta, eventIds, debitDelta = 0) {
    const key = player.toLowerCase();
    const prev = batchQueue.get(key) || { score: 0, tx: 0, debit: 0, firstAt: Date.now(), eventIds: new Set() };

    // Ne comptabiliser que si des eventIds nouveaux existent (quand eventIds est fourni)
    let newIds = [];
    if (Array.isArray(eventIds)) {
        for (const id of eventIds) {
            if (!prev.eventIds.has(id) && !processingEvents.has(id)) {
                newIds.push(id);
            }
        }
    }

    if (newIds.length === 0 && Array.isArray(eventIds) && eventIds.length > 0) {
        batchQueue.set(key, prev);
        return;
    }

    prev.score = Number(prev.score) + Number(scoreDelta || 0);
    prev.tx = Number(prev.tx) + Number(txDelta || 0);
    prev.debit = Number(prev.debit) + Number(debitDelta || 0);

    for (const id of newIds) {
        prev.eventIds.add(id);
        processingEvents.add(id);
    }
    batchQueue.set(key, prev);
}

async function flushBatchIfNeeded(force = false) {
    const now = Date.now();
    if (!ENABLE_MONAD_BATCH) return;
    if (isFlushing) return;
    if (!force && now - lastFlushAt < BATCH_FLUSH_MS) return;
    if (batchQueue.size === 0) return;
    
    isFlushing = true;
    try {
            // Préparer tuples
        const entries = Array.from(batchQueue.entries());
        // Partitionner en chunks de taille BATCH_MAX
        for (let i = 0; i < entries.length; i += BATCH_MAX) {
            const chunk = entries.slice(i, i + BATCH_MAX);
                const dataTuples = chunk
                    .map(([addr, agg]) => ({ addr, agg }))
                    .filter(({ agg }) => Number(agg.score || 0) > 0)
                    .map(({ addr, agg }) => ({
                        player: addr,
                        score: ethers.BigNumber.from(agg.score),
                        transactions: ethers.BigNumber.from(agg.tx)
                    }));

                // Appel on-chain batch (tuple[])
            const rpcUrl = process.env.MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz/';
            const provider = new ethers.providers.JsonRpcProvider(rpcUrl);
            const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
            const MONAD_GAMES_ID_CONTRACT = '0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0';
            const contractABI = [
                    'function batchUpdatePlayerData((address player,uint256 score,uint256 transactions)[] data)'
            ];
            const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet);

                if (dataTuples.length === 0) {
                    continue; // rien à envoyer dans ce chunk
                }
                console.log(`[Monad Games ID][BATCH] Flushing ${dataTuples.length} updates...`);

                // Preflight
                try {
                    await contract.callStatic.batchUpdatePlayerData(dataTuples);
                } catch (e) {
                    console.warn('[Monad Games ID][BATCH] preflight failed:', e.message || e);
                    continue; // ne vide pas le chunk, on réessaiera plus tard
                }

                // Gas estimate (+20%)
                let gasLimit = ethers.BigNumber.from(600000);
                try {
                    const est = await contract.estimateGas.batchUpdatePlayerData(dataTuples);
                    gasLimit = est.mul(120).div(100);
                } catch (_) {}

            const nonce = await getNextNonce(wallet);
                const tx = await contract.batchUpdatePlayerData(dataTuples, {
                    gasLimit,
                maxPriorityFeePerGas: ethers.utils.parseUnits('2', 'gwei'),
                maxFeePerGas: ethers.utils.parseUnits('100', 'gwei'),
                nonce
            });
            console.log(`[Monad Games ID][BATCH] Tx sent: ${tx.hash}`);
            // Backoff simple et attente confirmable
            const receipt = await tx.wait().catch(async (e) => {
                console.warn('[Monad Games ID][BATCH] wait() failed, retrying once in 1s:', e.message || e);
                await new Promise(r => setTimeout(r, 1000));
                return tx.wait();
            });
            console.log(`[Monad Games ID][BATCH] Confirmed in block ${receipt.blockNumber} (gasUsed=${receipt.gasUsed.toString()})`);

            // Marquer les événements utilisés comme traités (idempotence) puis retirer du buffer
            for (const [addr, agg] of chunk) {
                if (agg.eventIds && agg.eventIds.size) {
                    for (const id of agg.eventIds) {
                        processedEvents.add(id);
                        processingEvents.delete(id); // nettoyage des events en cours
                    }
                }
                batchQueue.delete(addr);
            }
            saveProcessedEvents(processedEvents);
        }
    } catch (err) {
        console.error('[Monad Games ID][BATCH] Flush error:', err.message || err);
        // on laisse les données dans la queue pour retry au prochain flush
    } finally {
        lastFlushAt = Date.now();
        isFlushing = false;
    }
}

if (ENABLE_MONAD_BATCH) {
    setInterval(() => {
        flushBatchIfNeeded();
        // Sécurité: flush forcé si attente > BATCH_MAX_WAIT_MS
        if (Date.now() - lastFlushAt > BATCH_MAX_WAIT_MS) {
            flushBatchIfNeeded(true);
        }
    }, Math.min(BATCH_FLUSH_MS, 1000)).unref();
}

// Mutex pour sérialiser les tx du serveur (éviter collisions nonce)
let serverTxMutex = false;

async function getNextNonce(wallet) {
    try {
        // Utiliser 'pending' pour éviter les collisions de nonce
        const nonce = await wallet.getTransactionCount('pending');
        console.log(`[NONCE] Nonce récupéré depuis blockchain: ${nonce}`);
        return nonce;
    } catch (error) {
        console.error('[NONCE] Erreur récupération nonce:', error);
        throw error;
    }
}

app.post('/api/monad-games-id/update-player', requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const { playerAddress, appKitWallet, actionType, txHash } = req.body || {};

        if (!playerAddress || !appKitWallet || !actionType || !txHash) {
            return res.status(400).json({ error: 'Missing required parameters (playerAddress, appKitWallet, actionType, txHash)' });
        }

        const pa = String(playerAddress).toLowerCase();
        const ak = String(appKitWallet).toLowerCase();

        console.log(`[Monad Games ID] Received request: ${actionType} for ${pa}`);
        console.log(`[Monad Games ID] AppKit wallet: ${ak}`);
        console.log(`[Monad Games ID] txHash: ${txHash}`);

        // Garde anti-concurrence sur le même txHash
        if (processingTxHashes.has(txHash)) {
            return res.status(409).json({ error: 'Transaction already being processed' });
        }
        processingTxHashes.add(txHash);
        res.on('finish', () => { processingTxHashes.delete(txHash); });

        // Évaluer l'état de liaison pour orienter la réponse finale, sans bloquer la consommation de points
        const existingBinding = walletBindings.get(pa);
        const mismatchBinding = !!(existingBinding && String(existingBinding).toLowerCase() !== ak);

        // (Déplacé) Liaison anti-farming après validations on-chain (création/validation de la liaison)

        // Vérification onchain de la tx ChogTanks
        const rpcUrl = process.env.MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz/';
        const provider = new ethers.providers.JsonRpcProvider(rpcUrl);

        // Attendre l'indexation du receipt avec retries pour éviter 404
        const MAX_WAIT_MS = Number(process.env.TX_RECEIPT_MAX_WAIT_MS || 15000);
        const RETRY_MS    = Number(process.env.TX_RECEIPT_RETRY_MS || 1000);
        let receipt = null;
        {
            const startAt = Date.now();
            while (Date.now() - startAt < MAX_WAIT_MS) {
                receipt = await provider.getTransactionReceipt(txHash);
                if (receipt) break;
                await new Promise(r => setTimeout(r, RETRY_MS));
            }
        }
        if (!receipt) {
            res.set('Retry-After', Math.ceil((Number(process.env.TX_RECEIPT_RETRY_MS || 1000))/1000).toString());
            return res.status(202).json({ pending: true, message: 'Awaiting transaction indexing' });
        }
        if (receipt.status !== 1) {
            return res.status(409).json({ error: 'Transaction failed on-chain' });
        }
        if (receipt.from && String(receipt.from).toLowerCase() !== ak) {
            return res.status(403).json({ error: 'Tx signer does not match bound AppKit wallet' });
        }

        const CHOGTANKS_CONTRACT_ADDRESS = (process.env.CHOGTANKS_CONTRACT_ADDRESS || '').toLowerCase();
        if (!CHOGTANKS_CONTRACT_ADDRESS) {
            return res.status(500).json({ error: 'Server misconfigured: CHOGTANKS_CONTRACT_ADDRESS missing' });
        }

const chogIface = new ethers.utils.Interface([
    'event NFTMinted(address indexed owner, uint256 tokenId)',
    'event NFTEvolved(address indexed owner, uint256 tokenId, uint256 newLevel, uint256 pointsConsumed)'
]);

        let derivedScore = 0;
        let derivedTx = 0;

        const eventIds = [];
        for (let idx = 0; idx < (receipt.logs || []).length; idx++) {
            const log = receipt.logs[idx];
            if (String(log.address).toLowerCase() !== CHOGTANKS_CONTRACT_ADDRESS) continue;
            try {
                const parsed = chogIface.parseLog(log);
                if (actionType === 'mint' && parsed.name === 'NFTMinted') {
                    const owner = String(parsed.args.owner).toLowerCase();
                    if (owner !== ak) continue;
                    const evId = `${txHash}:${idx}`;
                    if (processedEvents.has(evId)) {
                        console.log(`[IDEMPOTENCE] Event already processed: ${evId}`);
                        continue;
                    }
                    derivedScore += 100; // politique: +100 par mint
                    derivedTx += 1;
                    eventIds.push(evId);
                }
                if (actionType === 'evolve' && parsed.name === 'NFTEvolved') {
                    const owner = String(parsed.args.owner).toLowerCase();
                    if (owner !== ak) continue;
                    const newLevel = Number(parsed.args.newLevel || 0);
                    const pointsConsumed = Number(parsed.args.pointsConsumed || 0);
                    const evolutionCosts = { 2: 2, 3: 100, 4: 200, 5: 300, 6: 400, 7: 500, 8: 600, 9: 700, 10: 800 };
                    const cost = pointsConsumed > 0 ? pointsConsumed : (evolutionCosts[newLevel] || 0);
                    if (cost > 0) {
                        const evId = `${txHash}:${idx}`;
                        if (processedEvents.has(evId)) {
                            console.log(`[IDEMPOTENCE] Event already processed: ${evId}`);
                            continue;
                        }
                        derivedScore += cost;
                        derivedTx += 1;
                        eventIds.push(evId);
                    }
                }
            } catch (_) {
                // log non pertinent
            }
        }

        if (derivedScore <= 0 && derivedTx <= 0) {
            return res.status(422).json({ error: 'No matching on-chain event for provided actionType' });
        }

        // Consommation de points côté serveur APRÈS confirmation on-chain (indépendant du binding)
        if (actionType === 'evolve' && derivedScore > 0 && process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
            try {
                const admin = require('firebase-admin');
                if (!admin.apps.length) {
                    const serviceAccount = {
                        type: "service_account",
                        project_id: process.env.FIREBASE_PROJECT_ID,
                        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
                        private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
                        client_email: process.env.FIREBASE_CLIENT_EMAIL,
                        client_id: process.env.FIREBASE_CLIENT_ID,
                        auth_uri: "https://accounts.google.com/o/oauth2/auth",
                        token_uri: "https://oauth2.googleapis.com/token",
                        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
                        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
                    };
                    admin.initializeApp({
                        credential: admin.credential.cert(serviceAccount),
                        projectId: process.env.FIREBASE_PROJECT_ID
                    });
                }
                const db = admin.firestore();
                const docRef = db.collection('WalletScores').doc(pa);
                await db.runTransaction(async (t) => {
                    const snap = await t.get(docRef);
                    const current = snap.exists ? Number(snap.data().score || 0) : 0;
                    const next = Math.max(0, current - derivedScore);
                    t.set(docRef, { score: next, walletAddress: pa, lastUpdated: admin.firestore.FieldValue.serverTimestamp(), lastEvolutionTimestamp: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
                });
                console.log(`[POINTS] ✅ Décrément appliqué après evolve: -${derivedScore} pour ${pa}`);
            } catch (debitErr) {
                console.error('[POINTS] ❌ Échec décrément points:', debitErr.message || debitErr);
            }
        }

        // En cas de mismatch de liaison, répondre 403 après consommation des points (pas d'update binding/monad)
        if (mismatchBinding) {
            return res.status(403).json({
                error: "Wallet farming detected",
                details: "This Monad Games ID account is bound to a different AppKit wallet"
            });
        }

        // ANTI-FARMING: Établir/valider la liaison maintenant que tout est cohérent
        {
            const boundWallet = walletBindings.get(pa);
            if (!boundWallet) {
                walletBindings.set(pa, ak);
                saveWalletBindings(walletBindings);
                console.log(`[ANTI-FARMING] 🔗 Liaison confirmée: Privy ${pa} → AppKit ${ak}`);
            } else {
                console.log(`[ANTI-FARMING] ✅ Wallet vérifié: ${ak}`);
            }
        }

        if (ENABLE_MONAD_BATCH) {
            // En mode strict, on prépare aussi un débit égal au score dérivé
            const debitDelta = STRICT_POINTS ? derivedScore : 0;
            enqueuePlayerUpdate(pa, derivedScore, derivedTx, eventIds, debitDelta);
            return res.json({ 
                success: true, 
                queued: true,
                playerAddress: pa,
                scoreAmount: derivedScore,
                transactionAmount: derivedTx,
                actionType,
                verified: true
            });
        } else {
            // Sérialiser les tx du serveur pour éviter les collisions de nonce
            while (serverTxMutex) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
            serverTxMutex = true;
            
            try {
                const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
                const MONAD_GAMES_ID_CONTRACT = '0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0';
                const contractABI = [
                    'function updatePlayerData((address player,uint256 score,uint256 transactions) data)'
                ];
                const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet);

                const dataTuple = { player: pa, score: ethers.BigNumber.from(derivedScore), transactions: ethers.BigNumber.from(derivedTx) };
                console.log(`[Monad Games ID] Calling updatePlayerData tuple for ${pa}: score=${derivedScore}, tx=${derivedTx})`);
                // Preflight
                try {
                    await contract.callStatic.updatePlayerData(dataTuple);
                } catch (e) {
                    return res.status(409).json({ error: 'Preflight failed', details: e.message || String(e) });
                }
                let gasLimit = ethers.BigNumber.from(150000);
                try {
                    const est = await contract.estimateGas.updatePlayerData(dataTuple);
                    gasLimit = est.mul(120).div(100);
                } catch (_) {}
                const nonce = await getNextNonce(wallet);
                const tx = await contract.updatePlayerData(dataTuple, {
                    gasLimit,
                    gasLimit: 150000,
                    maxPriorityFeePerGas: ethers.utils.parseUnits('2', 'gwei'),
                    maxFeePerGas: ethers.utils.parseUnits('100', 'gwei'),
                    nonce
                });
                console.log(`[Monad Games ID] Transaction sent: ${tx.hash}`);
                const r = await tx.wait();
                console.log(`[Monad Games ID] Transaction confirmed in block ${r.blockNumber}`);

                // Marquer immédiatement les events comme traités (single) et persister
                for (const id of eventIds) processedEvents.add(id);
                saveProcessedEvents(processedEvents);

            // STRICT_POINTS: décrémenter les points côté serveur APRÈS confirmation on-chain
            if (STRICT_POINTS && derivedScore > 0 && process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
                try {
                    const admin = require('firebase-admin');
                    if (!admin.apps.length) {
                        const serviceAccount = {
                            type: "service_account",
                            project_id: process.env.FIREBASE_PROJECT_ID,
                            private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
                            private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
                            client_email: process.env.FIREBASE_CLIENT_EMAIL,
                            client_id: process.env.FIREBASE_CLIENT_ID,
                            auth_uri: "https://accounts.google.com/o/oauth2/auth",
                            token_uri: "https://oauth2.googleapis.com/token",
                            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
                            client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
                        };
                        admin.initializeApp({
                            credential: admin.credential.cert(serviceAccount),
                            projectId: process.env.FIREBASE_PROJECT_ID
                        });
                    }
                    const db = admin.firestore();
                    const docRef = db.collection('WalletScores').doc(pa);
                    await db.runTransaction(async (t) => {
                        const snap = await t.get(docRef);
                        const current = snap.exists ? Number(snap.data().score || 0) : 0;
                        const next = Math.max(0, current - derivedScore);
                        t.set(docRef, { score: next, walletAddress: pa, lastUpdated: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
                    });
                    console.log(`[STRICT_POINTS] ✅ Décrément appliqué: -${derivedScore} pour ${pa}`);
                } catch (debitErr) {
                    console.error('[STRICT_POINTS] Échec décrément points:', debitErr.message || debitErr);
                }
            }

                return res.json({ 
                    success: true, 
                    transactionHash: tx.hash, 
                    blockNumber: r.blockNumber, 
                    gasUsed: r.gasUsed.toString(),
                    playerAddress: pa, 
                    scoreAmount: derivedScore, 
                    transactionAmount: derivedTx, 
                    actionType,
                    verified: true,
                    message: 'Score submitted to Monad Games ID contract'
                });
            } finally {
                serverTxMutex = false;
            }
        }

    } catch (error) {
        console.error('[Monad Games ID] Error:', error);
        res.status(500).json({ 
            error: "Failed to submit to Monad Games ID", 
            details: error.message 
        });
    }
});

const server = app.listen(port, () => {
    console.log(`Signature server running on port ${port}`);
    console.log(`Game Server Address: ${gameWallet ? gameWallet.address : 'N/A (no private key)'}`);
});

// Réglages de timeouts HTTP (mitige 502 proxy Render)
try {
    server.keepAliveTimeout = Number(process.env.KEEP_ALIVE_TIMEOUT_MS || 65000);
    server.headersTimeout = Number(process.env.HEADERS_TIMEOUT_MS || 66000);
    server.requestTimeout = Number(process.env.REQUEST_TIMEOUT_MS || 30000);
    console.log('[HTTP] timeouts configured');
} catch (_) {}

// Garde-fous contre les crashs silencieux
process.on('unhandledRejection', (reason) => {
    console.error('[unhandledRejection]', reason);
});
process.on('uncaughtException', (err) => {
    console.error('[uncaughtException]', err);
});
