const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
require('dotenv').config();

// Build tag (helps verify correct deployed revision visually in logs)
const BUILD_TAG = 'CT-SIG-2025-09-11-1';

// Firebase (optionnel) – vérification token ID (initialisation lazy, sans fallback caché)
let firebaseAdmin = null;
try { firebaseAdmin = require('firebase-admin'); } catch { /* module absent -> silencieux */ }
let firebaseInitialized = false;
const fs = require('fs'); // utilisé pour vérifier l'existence du fichier de service
function initFirebaseIfPossible() {
    if (!firebaseAdmin || firebaseInitialized) return;
    try {
        if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
            const pk = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g,'\n');
            firebaseAdmin.initializeApp({ credential: firebaseAdmin.credential.cert({
                projectId: process.env.FIREBASE_PROJECT_ID,
                clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
                privateKey: pk
            }) });
            firebaseInitialized = true; console.log('[FIREBASE] init (triple env vars)');
        } else if (process.env.FIREBASE_REQUIRE_AUTH === '1') {
            console.error('[FIREBASE] configuration manquante (FIREBASE_PROJECT_ID / FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY)');
        }
    } catch(e){ console.log('[FIREBASE] init skipped:', e.message); }
}
function requireFirebaseAuth(req,res,next){
    if (process.env.FIREBASE_REQUIRE_AUTH !== '1') return next(); // mode permissif si non forcé
    initFirebaseIfPossible();
    if (!firebaseInitialized) return res.status(503).json({ error:'Auth unavailable' });
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) return res.status(401).json({ error:'Missing token' });
    const token = auth.slice(7);
    firebaseAdmin.auth().verifyIdToken(token)
        .then(decoded => { req.firebaseUser = decoded; next(); })
        .catch(()=> res.status(401).json({ error:'Invalid token' }));
}

const app = express();
app.use(express.json());
app.use(cors());

const port = process.env.PORT || 3001;

// Clé serveur (signatures et tx) + provider RPC privé (Alchemy)
const ALCHEMY_RPC = 'https://monad-testnet.g.alchemy.com/v2/JD1BgcAhWzSNu8vHiT1chCKaHUq3kH6-';
let gameWallet = null;
let provider = null;
let txWallet = null; // wallet connecté au provider pour les transactions on-chain

function initInfra() {
    if (!process.env.GAME_SERVER_PRIVATE_KEY) {
        console.error('ERREUR: GAME_SERVER_PRIVATE_KEY non définie. Les endpoints signés seront désactivés.');
        return;
    }
    if (!provider) {
        provider = new ethers.providers.JsonRpcProvider(ALCHEMY_RPC);
        provider.getNetwork().then(n => console.log('[RPC] chainId:', n.chainId)).catch(()=>{});
    }
    if (!gameWallet) {
        gameWallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY);
        console.log('Game Server Signer Address:', gameWallet.address);
    }
    if (!txWallet) {
        txWallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
    }
}
initInfra();

// Préflight sécurité basique
function preflight() {
    const key = process.env.GAME_SERVER_PRIVATE_KEY || '';
    if (!/^0x[0-9a-fA-F]{64}$/.test(key)) {
        console.error('[PRECHECK] GAME_SERVER_PRIVATE_KEY format invalide. Attendu 0x + 64 hex.');
        process.exit(1);
    }
    if (process.env.FIREBASE_REQUIRE_AUTH === '1') {
        const ready = process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY;
        if (!ready) {
            console.error('[PRECHECK] Auth Firebase exigée mais variables manquantes (FIREBASE_PROJECT_ID / FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY).');
            console.error('[AIDE] Fournis ces exports (exemple):');
            console.error(' export FIREBASE_PROJECT_ID="ton_project"');
            console.error(' export FIREBASE_CLIENT_EMAIL="service-account@ton_project.iam.gserviceaccount.com"');
            console.error(' export FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n"');
            process.exit(1);
        }
    }
}
preflight();

function logSecuritySummary() {
    const fbRequired = process.env.FIREBASE_REQUIRE_AUTH === '1';
    console.log('================ SECURITY SUMMARY ================');
    console.log(`[BUILD] Tag: ${BUILD_TAG}`);
    // Minimal env diagnostic (no secret values) to confirm Render injected vars
    try {
        const diag = {
            GAME_SERVER_PRIVATE_KEY: process.env.GAME_SERVER_PRIVATE_KEY ? `present(len=${process.env.GAME_SERVER_PRIVATE_KEY.length})` : 'MISSING',
            FIREBASE_REQUIRE_AUTH: process.env.FIREBASE_REQUIRE_AUTH || 'not set',
            FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID ? 'present' : 'absent',
            FIREBASE_CLIENT_EMAIL: process.env.FIREBASE_CLIENT_EMAIL ? 'present' : 'absent',
            FIREBASE_PRIVATE_KEY: process.env.FIREBASE_PRIVATE_KEY ? `present(len=${process.env.FIREBASE_PRIVATE_KEY.length})` : 'absent'
        };
        console.log('[ENV-DIAG]', JSON.stringify(diag));
    } catch {}
    console.log(`[SECURITY] Firebase Auth: ${fbRequired ? (firebaseInitialized ? 'ENABLED (initialized)' : 'ENABLED (lazy init)') : 'DISABLED (dev mode)'}`);
    if (fbRequired && !firebaseInitialized) {
        console.log('[SECURITY] -> Sera initialisé lors de la première requête protégée.');
    }
    console.log(`[SECURITY] Score window: PLAYER_RATE_MAX=${process.env.PLAYER_RATE_MAX||3} sur ${(process.env.PLAYER_RATE_WINDOW_MS||300000)/1000}s (delta max update=${process.env.MAX_SINGLE_DELTA||1200})`);
    console.log(`[SECURITY] Window delta cap: ${process.env.MAX_WINDOW_DELTA||6000}`);
    console.log(`[SECURITY] Min interval entre updates: ${process.env.MIN_INTERVAL_MS||2000} ms`);
    console.log('[SECURITY] Wallet binding anti-farming: ACTIVE');
    console.log('==================================================');
}

// Middleware: exige la présence du wallet pour les routes nécessitant une signature/tx
function requireWallet(req, res, next) {
    if (!gameWallet) {
        return res.status(503).json({ error: 'Server wallet not configured' });
    }
    next();
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

// Expose configuration sécurité (lecture seule – pas de secrets)
app.get('/config-info', (req,res)=>{
    res.json({
        firebaseRequired: process.env.FIREBASE_REQUIRE_AUTH === '1',
        firebaseInitialized,
        walletAddress: gameWallet ? gameWallet.address : null,
        rateConfig: {
            MIN_INTERVAL_MS,
            PLAYER_RATE_WINDOW_MS,
            PLAYER_RATE_MAX,
            MAX_SINGLE_DELTA,
            MAX_WINDOW_DELTA
        },
        queueDepth
    });
});

app.post('/api/mint-authorization', requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const { playerAddress, mintCost } = req.body;
        
        if (!playerAddress || !mintCost) {
            return res.status(400).json({ error: "Adresse du joueur et coût de mint requis" });
        }
        
        const message = ethers.utils.solidityKeccak256(
            ['address', 'uint256'],
            [playerAddress, mintCost]
        );
        
    const signature = await gameWallet.signMessage(ethers.utils.arrayify(message));
        
        console.log(`Autorisation de mint générée pour ${playerAddress} avec un coût de ${mintCost}`);
        
        res.json({
            signature: signature,
            mintCost: mintCost,
            gameServerAddress: gameWallet.address
        });
        
    } catch (error) {
        console.error('Erreur d\'autorisation de mint:', error);
        res.status(500).json({ error: "Erreur interne du serveur" });
    }
});

app.post('/api/evolve-authorization', requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const playerAddress = req.body.playerAddress || req.body.walletAddress;
        const { tokenId, targetLevel } = req.body;
        
        console.log(`[EVOLVE-AUTH] Request body:`, req.body);
        console.log(`[EVOLVE-AUTH] Headers:`, req.headers);
        
        if (!playerAddress || !tokenId || !targetLevel) {
            return res.status(400).json({ error: "Adresse du joueur, ID du token et niveau cible requis" });
        }

        // Auth Firebase déjà vérifiée par requireFirebaseAuth middleware
        console.log(`[EVOLVE-AUTH] ✅ Firebase UID: ${req.uid}`);
        
        // Vérification ownership wallet
        const ownership = await assertWalletBelongsToUid(playerAddress, req.uid);
        if (!ownership.ok) {
            return res.status(403).json({ error: 'Wallet not linked to user', reason: ownership.reason });
        }
        
        const evolutionCosts = {
            1: 50,   // Level 0 -> 1
            2: 100,  // Level 1 -> 2
            3: 150,  // Level 2 -> 3
            4: 200,  // Level 3 -> 4
            5: 300,  // Level 4 -> 5
            6: 400,  // Level 5 -> 6
            7: 500,  // Level 6 -> 7
            8: 600,  // Level 7 -> 8
            9: 700,  // Level 8 -> 9
            10: 800  // Level 9 -> 10
        };
        
        const requiredPoints = evolutionCosts[targetLevel];
        
        if (!requiredPoints) {
            return res.status(400).json({ error: "Niveau cible invalide" });
        }
        
        const message = ethers.utils.solidityKeccak256(
            ['address', 'uint256', 'uint256', 'uint256'],
            [playerAddress, tokenId, targetLevel, requiredPoints]
        );
        
    const signature = await gameWallet.signMessage(ethers.utils.arrayify(message));
        
        console.log(`Autorisation d'évolution générée pour ${playerAddress}, token ${tokenId} vers niveau ${targetLevel}`);
        
        res.json({
            signature: signature,
            evolutionCost: requiredPoints,
            targetLevel: targetLevel
        });
        
    } catch (error) {
        console.error('Evolve authorization error:', error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Anti-farming: Stockage persistant des liaisons wallet
// (fs déjà importé plus haut)
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

async function getNextNonce(wallet) {
    return wallet.getTransactionCount('latest');
}

// Queue séquentielle très légère pour éviter collisions nonce sous burst
let txQueue = Promise.resolve();
let queueDepth = 0;
const MAX_QUEUE_DEPTH = 40; // Backpressure guard
function enqueueTx(fn, res) {
    if (queueDepth >= MAX_QUEUE_DEPTH) {
        if (res && !res.headersSent) res.status(503).json({ error: 'Server busy, retry later' });
        return;
    }
    queueDepth++;
    txQueue = txQueue
        .then(() => fn())
        .catch(e => console.error('[QUEUE]', e.message))
        .finally(() => { queueDepth--; });
    return txQueue;
}

// Simple fixed-window rate limit per IP (lightweight, in-memory)
const rateBuckets = new Map();
const WINDOW_MS = 10_000; // 10s window
const MAX_REQ = 30;       // per IP per window (tune as needed)
function rateLimit(req, res, next) {
    const ip = req.headers['x-forwarded-for']?.toString().split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let b = rateBuckets.get(ip);
    if (!b || now - b.start > WINDOW_MS) {
        b = { start: now, count: 0 };
    }
    b.count++;
    rateBuckets.set(ip, b);
    if (b.count > MAX_REQ) {
        return res.status(429).json({ error: 'Too many requests' });
    }
    next();
}

// =====================
// Minimal score validation & per-player throttling
// =====================
const pathLastScores = path.join(__dirname, 'last-scores.json');
// Score validation tuning (env overrides supported)
// Définitions:
//  - delta (par update) = nouveauScoreSoumis - dernierScoreAccepté
//  - fenêtre = période PLAYER_RATE_WINDOW_MS (ex: 5 min) utilisée aussi pour plafonner l'accumulation totale
// Constraints:
//  (1) Monotonicité (pas de régression)
//  (2) Delta par update <= MAX_SINGLE_DELTA (ex: permettre une évolution ~900-1000)
//  (3) Somme des deltas acceptés dans la fenêtre courante <= MAX_WINDOW_DELTA (rarement > ~5000 selon ton retour)
//  (4) Espacement minimal entre updates (MIN_INTERVAL_MS)
//  (5) Nombre maximal d'updates acceptées dans la fenêtre (PLAYER_RATE_MAX)
const MIN_INTERVAL_MS = Number(process.env.MIN_INTERVAL_MS || 2000);
const PLAYER_RATE_WINDOW_MS = Number(process.env.PLAYER_RATE_WINDOW_MS || 300000); // 5 min
const PLAYER_RATE_MAX = Number(process.env.PLAYER_RATE_MAX || 3); // ex: 2 ou 3 attendu
const MAX_SINGLE_DELTA = Number(process.env.MAX_SINGLE_DELTA || 1200); // >1000 pour marge evolution
// Mettre MAX_WINDOW_DELTA=0 pour désactiver totalement le plafond cumul fenêtre
const MAX_WINDOW_DELTA = Number(process.env.MAX_WINDOW_DELTA || 6000); // 0 => disabled

let lastScores = new Map(); // playerAddress -> { score, lastAt, windowStart, count, windowDelta }
const metrics = {
    accepted: 0,
    rejectedDelta: 0,
    rejectedRegression: 0,
    rejectedThrottle: 0,
    rejectedRate: 0,
    rejectedWindowDelta: 0
};

function loadLastScores() {
    try {
        if (fs.existsSync(pathLastScores)) {
            const raw = JSON.parse(fs.readFileSync(pathLastScores,'utf8'));
            lastScores = new Map(Object.entries(raw));
        }
    } catch(e){ console.error('[SCORES] load error', e.message); }
}
function persistLastScores() {
    try {
        const tmp = pathLastScores + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(lastScores), null, 2));
        fs.renameSync(tmp, pathLastScores);
    } catch(e){ console.error('[SCORES] persist error', e.message); }
}
loadLastScores();

function validateAndRecordScore(playerAddress, newScore) {
    const now = Date.now();
    const rec = lastScores.get(playerAddress) || { score: 0, lastAt: 0, windowStart: now, count: 0, windowDelta: 0 };
    if (newScore < rec.score) { metrics.rejectedRegression++; return { ok:false, code:400, msg:'Score regression' }; }
    const delta = newScore - rec.score;
    if (delta > MAX_SINGLE_DELTA) { metrics.rejectedDelta++; return { ok:false, code:400, msg:`Delta too large (> ${MAX_SINGLE_DELTA})` }; }
    if (now - rec.lastAt < MIN_INTERVAL_MS) { metrics.rejectedThrottle++; return { ok:false, code:429, msg:'Too fast' }; }
    if (now - rec.windowStart > PLAYER_RATE_WINDOW_MS) { rec.windowStart = now; rec.count = 0; rec.windowDelta = 0; }
    // Plafond cumul fenêtre
    if (MAX_WINDOW_DELTA > 0 && (rec.windowDelta + delta) > MAX_WINDOW_DELTA) { metrics.rejectedWindowDelta++; return { ok:false, code:400, msg:`Window delta limit (> ${MAX_WINDOW_DELTA})` }; }
    rec.count++;
    if (rec.count > PLAYER_RATE_MAX) { metrics.rejectedRate++; return { ok:false, code:429, msg:'Rate limit player' }; }
    // accept
    rec.score = newScore;
    rec.lastAt = now;
    rec.windowDelta += delta;
    lastScores.set(playerAddress, rec);
    metrics.accepted++;
    // Persist synchronously (low frequency expected) - could be buffered later
    persistLastScores();
    return { ok:true };
}

// Metrics endpoint
app.get('/metrics', (req,res)=>{
    res.json({
        queueDepth,
        trackedPlayers: lastScores.size,
        ...metrics,
    config: { MIN_INTERVAL_MS, PLAYER_RATE_WINDOW_MS, PLAYER_RATE_MAX, MAX_SINGLE_DELTA, MAX_WINDOW_DELTA }
    });
});

// Simple allowlisted JSON-RPC proxy (no private key exposure client-side if used)
const RPC_METHOD_ALLOWLIST = new Set(['eth_blockNumber','eth_chainId','eth_call','eth_getLogs']);
app.post('/rpc', rateLimit, async (req,res)=>{
    const { method, params, id } = req.body || {};
    if (!method || !RPC_METHOD_ALLOWLIST.has(method)) return res.status(403).json({ error:'method not allowed' });
    try {
        if (!provider) return res.status(503).json({ error:'provider not ready' });
        const result = await provider.send(method, params || []);
        res.json({ jsonrpc:'2.0', id: id ?? 1, result });
    } catch(e){
        console.error('[RPC-PROXY]', e.message);
        res.status(500).json({ error:'rpc error' });
    }
});

app.post('/api/monad-games-id/update-player', rateLimit, requireWallet, requireFirebaseAuth, async (req, res) => {
    enqueueTx(async () => {
        try {
            const { playerAddress, appKitWallet, scoreAmount, transactionAmount } = req.body; // actionType ignoré (plus utilisé)
            if (!playerAddress || !appKitWallet || scoreAmount === undefined || transactionAmount === undefined) {
                return res.status(400).json({ error: 'Missing required parameters' });
            }
            // Validate score progression (simple, non-batch logic)
            const validation = validateAndRecordScore(playerAddress.toLowerCase(), Number(scoreAmount));
            if (!validation.ok) {
                return res.status(validation.code).json({ error: validation.msg });
            }
            const boundWallet = walletBindings.get(playerAddress);
            if (!boundWallet) {
                walletBindings.set(playerAddress, appKitWallet);
                saveWalletBindings(walletBindings);
            } else if (boundWallet !== appKitWallet) {
                return res.status(403).json({ error: 'Wallet farming detected' });
            }
            if (!txWallet) return res.status(503).json({ error: 'Tx wallet unavailable' });
            const contractAddress = '0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0';
            const contractABI = ["function updatePlayerData(address player, uint256 scoreAmount, uint256 transactionAmount)"];
            const contract = new ethers.Contract(contractAddress, contractABI, txWallet);
        // Nonce laissé au gestionnaire interne d'ethers (séquence sécurisée par la queue)
        const tx = await contract.updatePlayerData(playerAddress, scoreAmount, transactionAmount, { gasLimit: 150000 });
            console.log('[UPDATE] Tx sent', tx.hash);
            const receipt = await tx.wait();
            console.log('[UPDATE] Confirmed block', receipt.blockNumber);
            if (!res.headersSent) res.json({ success: true, transactionHash: tx.hash, blockNumber: receipt.blockNumber, playerAddress, scoreAmount, transactionAmount });
        } catch (error) {
            console.error('[UPDATE] Error:', error.message);
            if (!res.headersSent) res.status(500).json({ error: 'Failed to submit', details: error.message });
        }
    }, res);
});

app.listen(port, () => {
    console.log(`[START] Signature server running on port ${port}`);
    console.log(`[START] Game server signer: ${gameWallet ? gameWallet.address : 'N/A (no private key)'}`);
    logSecuritySummary();
});

// Garde-fous contre les crashs silencieux
process.on('unhandledRejection', (reason) => {
    console.error('[unhandledRejection]', reason);
});
process.on('uncaughtException', (err) => {
    console.error('[uncaughtException]', err);
});
