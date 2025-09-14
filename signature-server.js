const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
let helmet = null;
require('dotenv').config();

const app = express();
app.disable('x-powered-by');
try {
    helmet = require('helmet');
    app.use(helmet());
} catch (_) {
    console.warn('[BOOT] helmet non installé - en-têtes sécurité non appliqués');
}
app.use(express.json());
// Rate limit simple (optionnel via RATE_LIMIT_WINDOW_MS/RATE_LIMIT_MAX)
try {
    const rateLimit = require('express-rate-limit');
    const windowMs = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000); // 1 min
    const max = Number(process.env.RATE_LIMIT_MAX || 300); // 300 req/min par IP
    app.use(rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false }));
} catch (_) {
    console.warn('[BOOT] express-rate-limit non installé - pas de rate limit');
}

// CORS restrictif (configurable par ALLOWED_ORIGINS)
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
app.use(cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, true); // allow non-browser tools
        if (allowedOrigins.has(origin)) return cb(null, true);
        return cb(new Error('Not allowed by CORS'));
    },
    credentials: true
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

app.post('/api/match/start', requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        console.log(`[MATCH-START] Match start requested`);
        
        // Générer un token de match unique
        const matchToken = Math.random().toString(36).slice(2) + Date.now().toString(36);
        const expiresInMs = Number(process.env.MATCH_TOKEN_TTL_MS || (2 * 60 * 1000)); // défaut 2 minutes
        const now = Date.now();
        const uid = req.firebaseAuth?.uid || null;
        matchTokens.set(matchToken, {
            uid,
            createdAt: now,
            expAt: now + expiresInMs,
            used: false
        });
        
        console.log(`[MATCH-START] Generated match token: ${matchToken}`);
        
        return res.json({
            matchToken: matchToken,
            expiresInMs: expiresInMs,
            success: true
        });
    } catch (error) {
        console.error('[MATCH-START] Error:', error);
        res.status(500).json({ error: 'Failed to start match', details: error.message });
    }
});

// Endpoint pour soumettre les scores (compatibilité ancien build)
app.post('/api/firebase/submit-score', requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const { walletAddress, score, bonus, matchId, matchToken } = req.body || {};
        if (!walletAddress || typeof score === 'undefined') {
            return res.status(400).json({ error: 'Missing walletAddress or score' });
        }
        if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
            return res.status(400).json({ error: 'Invalid wallet address format' });
        }
        
        const normalized = walletAddress.toLowerCase();
        const totalScore = (parseInt(score, 10) || 0) + (parseInt(bonus, 10) || 0);

        // Enforce match token usage si auth active
        if (process.env.FIREBASE_REQUIRE_AUTH === '1') {
            if (!matchToken || typeof matchToken !== 'string') {
                return res.status(400).json({ error: 'Missing matchToken' });
            }
            const rec = matchTokens.get(matchToken);
            if (!rec) {
                return res.status(401).json({ error: 'Invalid matchToken' });
            }
            if (rec.used) {
                return res.status(401).json({ error: 'Match token already used' });
            }
            if (rec.expAt < Date.now()) {
                matchTokens.delete(matchToken);
                return res.status(401).json({ error: 'Match token expired' });
            }
            const uid = req.firebaseAuth?.uid || null;
            if (rec.uid && uid && rec.uid !== uid) {
                return res.status(401).json({ error: 'Match token does not belong to this user' });
            }
            rec.used = true;
            matchTokens.set(matchToken, rec);
        }
        
        console.log(`[SUBMIT-SCORE] Score submitted for ${normalized}: ${totalScore} (base: ${score}, bonus: ${bonus})`);
        
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
                
                // Ajouter le nouveau score
                const newTotalScore = currentScore + totalScore;
                
                // Sauvegarder dans Firebase
                await docRef.set({
                    score: newTotalScore,
                    walletAddress: normalized,
                    lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
                    matchId: matchId || 'legacy'
                }, { merge: true });
                
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

        if (!playerAddress) {
            return res.status(400).json({ error: "Adresse du joueur requise" });
        }

        // Schéma robuste aligné contrat: (msg.sender, playerPoints, nonce, "MINT")
        if (typeof playerPoints !== 'undefined') {
            const nonce = Date.now();
            const message = ethers.utils.solidityKeccak256(
                ['address', 'uint256', 'uint256', 'string'],
                [playerAddress, ethers.BigNumber.from(playerPoints), ethers.BigNumber.from(nonce), 'MINT']
            );
            const signature = await gameWallet.signMessage(ethers.utils.arrayify(message));

            console.log(`[MINT] ✅ Autorisation (nouveau schéma) pour ${playerAddress}, points=${playerPoints}, nonce=${nonce}`);
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
            [playerAddress, ethers.BigNumber.from(mintCost)]
        );
        const signatureLegacy = await gameWallet.signMessage(ethers.utils.arrayify(messageLegacy));

        console.log(`[MINT] ✅ Autorisation (legacy) pour ${playerAddress}, mintCost=${mintCost}`);
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
        console.log(`[MONITORING] 🚀 EVOLVE REQUEST - Wallet: ${playerAddress}, Token: ${tokenId}, Target Level: ${targetLevel}, Cost: ${requiredPoints}, PlayerPoints: ${pointsForSignature}, Nonce: ${nonce}`);

        return res.json({
            authorized: true,
            signature,
            evolutionCost: requiredPoints,
            targetLevel,
            nonce
        });

    } catch (error) {
        console.error('Evolve authorization error:', error);
        return res.status(500).json({ error: "Internal server error" });
    }
});

// Anti-farming: Stockage persistant des liaisons wallet
const fs = require('fs');
const path = require('path');

const WALLET_BINDINGS_FILE = path.join(__dirname, 'wallet-bindings.json');

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
// Idempotence événements traités (anti-replay)
// =====================
const PROCESSED_EVENTS_FILE = path.join(__dirname, 'processed-events.json');
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

// =====================
// Débits de points (après confirmation on-chain)
// =====================
const POINTS_DEBIT_EVENTS_FILE = path.join(__dirname, 'points-debited-events.json');
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
    prev.score = Number(prev.score) + Number(scoreDelta || 0);
    prev.tx = Number(prev.tx) + Number(txDelta || 0);
    prev.debit = Number(prev.debit) + Number(debitDelta || 0);
    if (Array.isArray(eventIds)) {
        for (const id of eventIds) prev.eventIds.add(id);
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
        // Préparer tableaux
        const entries = Array.from(batchQueue.entries());
        // Partitionner en chunks de taille BATCH_MAX
        for (let i = 0; i < entries.length; i += BATCH_MAX) {
            const chunk = entries.slice(i, i + BATCH_MAX);
            const players = [];
            const scores = [];
            const txs = [];
            for (const [addr, agg] of chunk) {
                players.push(addr);
                scores.push(ethers.BigNumber.from(agg.score));
                txs.push(ethers.BigNumber.from(agg.tx));
            }

            // Appel on-chain batch
            const rpcUrl = process.env.MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz/';
            const provider = new ethers.providers.JsonRpcProvider(rpcUrl);
            const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
            const MONAD_GAMES_ID_CONTRACT = '0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0';
            const contractABI = [
                'function batchUpdatePlayerData(address[] players, uint256[] scoreAmounts, uint256[] transactionAmounts)'
            ];
            const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet);

            console.log(`[Monad Games ID][BATCH] Flushing ${players.length} updates...`);
            const nonce = await getNextNonce(wallet);
            const tx = await contract.batchUpdatePlayerData(players, scores, txs, {
                gasLimit: 600000, // batch → plus de gas
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
                    for (const id of agg.eventIds) processedEvents.add(id);
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

async function getNextNonce(wallet) {
    try {
        // Toujours récupérer le nonce le plus récent depuis la blockchain
        const nonce = await wallet.getTransactionCount('latest');
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

        // ANTI-FARMING: Vérifier/établir la liaison des wallets (normalisée)
        const boundWallet = walletBindings.get(pa);
        if (!boundWallet) {
            walletBindings.set(pa, ak);
            saveWalletBindings(walletBindings);
            console.log(`[ANTI-FARMING] 🔗 Liaison créée et sauvegardée: Privy ${pa} → AppKit ${ak}`);
        } else if (String(boundWallet).toLowerCase() !== ak) {
            console.error(`[ANTI-FARMING] 🚫 FARMING DÉTECTÉ! Privy=${pa}, Bound=${boundWallet}, Current=${ak}`);
            return res.status(403).json({ 
                error: "Wallet farming detected", 
                details: "This Monad Games ID account is bound to a different AppKit wallet"
            });
        } else {
            console.log(`[ANTI-FARMING] ✅ Wallet vérifié: ${ak}`);
        }

        // Vérification onchain de la tx ChogTanks
        const rpcUrl = process.env.MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz/';
        const provider = new ethers.providers.JsonRpcProvider(rpcUrl);

        const receipt = await provider.getTransactionReceipt(txHash);
        if (!receipt) {
            return res.status(404).json({ error: 'Transaction not found' });
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
            const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
            const MONAD_GAMES_ID_CONTRACT = '0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0';
            const contractABI = [
                'function updatePlayerData(address player, uint256 scoreAmount, uint256 transactionAmount)'
            ];
            const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet);

            console.log(`[Monad Games ID] Calling updatePlayerData(${pa}, ${derivedScore}, ${derivedTx})`);
            const nonce = await getNextNonce(wallet);
            const tx = await contract.updatePlayerData(pa, derivedScore, derivedTx, {
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
        }

    } catch (error) {
        console.error('[Monad Games ID] Error:', error);
        res.status(500).json({ 
            error: "Failed to submit to Monad Games ID", 
            details: error.message 
        });
    }
});

app.listen(port, () => {
    console.log(`Signature server running on port ${port}`);
    console.log(`Game Server Address: ${gameWallet ? gameWallet.address : 'N/A (no private key)'}`);
});

// Garde-fous contre les crashs silencieux
process.on('unhandledRejection', (reason) => {
    console.error('[unhandledRejection]', reason);
});
process.on('uncaughtException', (err) => {
    console.error('[uncaughtException]', err);
});
