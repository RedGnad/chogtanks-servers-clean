const express = require('express');
const { ethers } = require('ethers');
const crypto = require('crypto');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);

app.use(express.json({ limit: '10mb' })); // Limite de taille pour éviter les attaques
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
    origin: [
        'https://chogtanks.vercel.app',
        'https://redgnad.github.io', 
        'https://monadclip.com', 
        'https://*.monadclip.com'
    ],
    credentials: true
}));

// Rate limiting global pour éviter le spam
const requestCounts = new Map();
const GLOBAL_RATE_LIMIT = 100; // 100 req/min par IP
const RATE_WINDOW = 60000; // 1 minute

// ALCHEMY PROTECTION: Éviter de dépasser les limites gratuites
const alchemyUsage = { count: 0, resetTime: Date.now() + 60000 }; // Reset chaque minute
const ALCHEMY_FREE_LIMIT = 270; // 270 req/min (300 - 30 marge conservatrice)

app.use((req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    if (!requestCounts.has(clientIP)) {
        requestCounts.set(clientIP, { count: 1, resetTime: now + RATE_WINDOW });
    } else {
        const data = requestCounts.get(clientIP);
        if (now < data.resetTime) {
            if (data.count >= GLOBAL_RATE_LIMIT) {
                return res.status(429).json({ error: 'Too many requests' });
            }
            data.count++;
        } else {
            requestCounts.set(clientIP, { count: 1, resetTime: now + RATE_WINDOW });
        }
    }
    
    next();
});

// ALCHEMY PROTECTION: Middleware pour éviter de dépasser les limites
app.use((req, res, next) => {
    // Seulement pour les endpoints qui utilisent Alchemy
    if (req.path.includes('/api/monad-games-id/') || req.path.includes('/api/validate-score')) {
        const now = Date.now();
        
        // Reset counter chaque minute
        if (now > alchemyUsage.resetTime) {
            alchemyUsage.count = 0;
            alchemyUsage.resetTime = now + 60000;
        }
        
        // Vérifier la limite
        if (alchemyUsage.count >= ALCHEMY_FREE_LIMIT) {
            console.warn(`[ALCHEMY] ⚠️ Approaching free tier limit: ${alchemyUsage.count}/${ALCHEMY_FREE_LIMIT}`);
            return res.status(429).json({ 
                error: 'Service temporarily unavailable',
                message: 'Too many requests, please try again later',
                retryAfter: Math.ceil((alchemyUsage.resetTime - now) / 1000)
            });
        }
        
        alchemyUsage.count++;
    }
    
    next();
});

// FIREBASE ADMIN SDK - Pour validation sécurisée des scores
const admin = require('firebase-admin');

// Initialiser Firebase Admin (si pas déjà fait)
if (!admin.apps.length) {
    try {
        // Utiliser les variables d'environnement pour Firebase
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
        
        console.log('[FIREBASE] ✅ Admin SDK initialisé pour validation des scores');
    } catch (error) {
        console.error('[FIREBASE] ❌ Erreur initialisation Admin SDK:', error.message);
        console.warn('[FIREBASE] ⚠️ Validation des scores désactivée - config manquante');
    }
}

const port = process.env.PORT || 3001;

// Match tokens en mémoire: token -> { uid, expMs, used }
const matchTokens = new Map();
const MATCH_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes (matches last ~3-4 min)

// Helper: vérifie ID token Firebase, renvoie uid ou null
async function verifyFirebaseIdTokenFromRequest(req) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return null;
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        return decoded && decoded.uid ? decoded.uid : null;
    } catch (e) {
        return null;
    }
}

// Démarrage de match: génère un matchToken court-vivant lié au uid
app.post('/api/match/start', async (req, res) => {
    const uid = await verifyFirebaseIdTokenFromRequest(req);
    if (!uid) return res.status(401).json({ error: 'Unauthorized' });

    const token = crypto.randomBytes(32).toString('hex');
    const expMs = Date.now() + MATCH_TOKEN_TTL_MS;
    matchTokens.set(token, { uid, expMs, used: false });
    return res.json({ matchToken: token, expiresInMs: MATCH_TOKEN_TTL_MS });
});

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

// Health check endpoint pour monitoring (optimisé pour cron-job)
app.get('/health', (req, res) => {
    // Log minimal seulement si problème
    if (!gameWallet) {
        console.error('[HEALTH] ❌ Game wallet not configured');
    }
    
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        version: '2.0.0',
        walletReady: Boolean(gameWallet),
        rpc: 'Alchemy Monad Testnet',
        contract: '0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0'
    });
});

// Supporte aussi la méthode HEAD sur /health (pour cron-job)
app.head('/health', (req, res) => res.sendStatus(200));

app.post('/api/mint-authorization', requireWallet, async (req, res) => {
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

app.post('/api/evolve-authorization', requireWallet, async (req, res) => {
    try {
        const { playerAddress, tokenId, targetLevel } = req.body;
        
        if (!playerAddress || !tokenId || !targetLevel) {
            return res.status(400).json({ error: "Adresse du joueur, ID du token et niveau cible requis" });
        }
        
        const evolutionCosts = {
            1: 50,   // Level 0 -> 1
            2: 100,  // Level 1 -> 2
            3: 150,  // Level 2 -> 3
            4: 200   // Level 3 -> 4
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

// SECURITY: Rate limiting pour éviter le spam de scores
const scoreRateLimit = new Map(); // wallet -> { count, resetTime }
const SCORE_RATE_LIMIT = 10; // max 10 soumissions par minute
const SCORE_RATE_WINDOW = 60000; // 1 minute

// SECURITY: Validation des scores
const MAX_REASONABLE_SCORE = 1000; // Score maximum raisonnable par match
const MIN_SCORE_INTERVAL = 5000; // Minimum 5 secondes entre soumissions
const lastScoreSubmission = new Map(); // wallet -> timestamp

// ANTI-BOT: Détection de comportements suspects
const botDetection = new Map(); // IP -> { count, lastActivity, suspicious }
const BOT_THRESHOLD = 20; // 20 requêtes en 1 minute = suspect
const BOT_BAN_DURATION = 300000; // 5 minutes de ban
const suspiciousIPs = new Set(); // IPs bannies temporairement

// SECURITY: Fonction de validation des scores
function validateScoreSubmission(walletAddress, scoreAmount, transactionAmount) {
    const now = Date.now();
    
    // 1. Rate limiting
    const rateLimitData = scoreRateLimit.get(walletAddress);
    if (rateLimitData) {
        if (now < rateLimitData.resetTime) {
            if (rateLimitData.count >= SCORE_RATE_LIMIT) {
                console.error(`[SECURITY] 🚫 Rate limit exceeded for ${walletAddress}: ${rateLimitData.count}/${SCORE_RATE_LIMIT}`);
                return { valid: false, reason: "Rate limit exceeded" };
            }
            rateLimitData.count++;
        } else {
            scoreRateLimit.set(walletAddress, { count: 1, resetTime: now + SCORE_RATE_WINDOW });
        }
    } else {
        scoreRateLimit.set(walletAddress, { count: 1, resetTime: now + SCORE_RATE_WINDOW });
    }
    
    // 2. Validation du score
    if (scoreAmount < 0 || scoreAmount > MAX_REASONABLE_SCORE) {
        console.error(`[SECURITY] 🚫 Invalid score amount: ${scoreAmount} for ${walletAddress}`);
        return { valid: false, reason: "Invalid score amount" };
    }
    
    // 3. Validation des transactions
    if (transactionAmount < 0 || transactionAmount > 100) {
        console.error(`[SECURITY] 🚫 Invalid transaction amount: ${transactionAmount} for ${walletAddress}`);
        return { valid: false, reason: "Invalid transaction amount" };
    }
    
    // 4. Intervalle minimum entre soumissions
    const lastSubmission = lastScoreSubmission.get(walletAddress);
    if (lastSubmission && (now - lastSubmission) < MIN_SCORE_INTERVAL) {
        console.error(`[SECURITY] 🚫 Too frequent submissions for ${walletAddress}: ${now - lastSubmission}ms`);
        return { valid: false, reason: "Too frequent submissions" };
    }
    
    lastScoreSubmission.set(walletAddress, now);
    
    console.log(`[SECURITY] ✅ Score validation passed for ${walletAddress}: score=${scoreAmount}, tx=${transactionAmount}`);
    return { valid: true };
}

// ANTI-BOT: Fonction de détection de bots
function detectBotBehavior(clientIP, userAgent, req) {
    const now = Date.now();
    
    // Vérifier si IP est bannie
    if (suspiciousIPs.has(clientIP)) {
        console.error(`[ANTI-BOT] 🚫 Banned IP attempting access: ${clientIP}`);
        return { isBot: true, reason: "IP temporarily banned" };
    }
    
    // Détecter patterns suspects
    const suspiciousPatterns = [
        /bot/i, /crawler/i, /spider/i, /scraper/i,
        /curl/i, /wget/i, /python/i, /java/i,
        /postman/i, /insomnia/i, /httpie/i
    ];
    
    if (userAgent && suspiciousPatterns.some(pattern => pattern.test(userAgent))) {
        console.error(`[ANTI-BOT] 🤖 Suspicious user agent: ${userAgent}`);
        return { isBot: true, reason: "Suspicious user agent" };
    }
    
    // Détecter requêtes trop rapides
    if (!botDetection.has(clientIP)) {
        botDetection.set(clientIP, { count: 1, lastActivity: now, suspicious: false });
    } else {
        const data = botDetection.get(clientIP);
        const timeDiff = now - data.lastActivity;
        
        if (timeDiff < 1000) { // Moins d'1 seconde entre requêtes
            data.count++;
            if (data.count > BOT_THRESHOLD) {
                data.suspicious = true;
                suspiciousIPs.add(clientIP);
                console.error(`[ANTI-BOT] 🚫 Bot detected: ${clientIP} - ${data.count} requests in ${timeDiff}ms`);
                
                // Auto-unban après 5 minutes
                setTimeout(() => {
                    suspiciousIPs.delete(clientIP);
                    botDetection.delete(clientIP);
                    console.log(`[ANTI-BOT] ✅ IP unbanned: ${clientIP}`);
                }, BOT_BAN_DURATION);
                
                return { isBot: true, reason: "Too many requests too fast" };
            }
        } else {
            // Reset counter si plus d'1 seconde
            data.count = 1;
        }
        
        data.lastActivity = now;
    }
    
    return { isBot: false };
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

app.post('/api/monad-games-id/update-player', requireWallet, async (req, res) => {
    const startTime = Date.now();
    const clientIP = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent');
    
    try {
        // ANTI-BOT: Détection de comportement suspect
        const botCheck = detectBotBehavior(clientIP, userAgent, req);
        if (botCheck.isBot) {
            console.error(`[ANTI-BOT] 🚫 Bot blocked: ${clientIP} - ${botCheck.reason}`);
            return res.status(403).json({ 
                error: "Bot detected", 
                reason: botCheck.reason 
            });
        }
        
        const { playerAddress, appKitWallet, scoreAmount, transactionAmount, actionType } = req.body;
        
        console.log(`[Monad Games ID] 🚀 NEW REQUEST - ${new Date().toISOString()}`);
        console.log(`[Monad Games ID] Action: ${actionType || 'unknown'}`);
        console.log(`[Monad Games ID] Player: ${playerAddress}`);
        console.log(`[Monad Games ID] AppKit Wallet: ${appKitWallet}`);
        console.log(`[Monad Games ID] Score: ${scoreAmount}, Transactions: ${transactionAmount}`);
        
        if (!playerAddress || !appKitWallet || scoreAmount === undefined || transactionAmount === undefined) {
            console.error(`[Monad Games ID] ❌ Missing parameters - Player: ${!!playerAddress}, AppKit: ${!!appKitWallet}, Score: ${scoreAmount}, Tx: ${transactionAmount}`);
            return res.status(400).json({ error: 'Missing required parameters' });
        }
        
        // SECURITY: Validation des scores avant traitement
        const validation = validateScoreSubmission(playerAddress, scoreAmount, transactionAmount);
        if (!validation.valid) {
            console.error(`[SECURITY] 🚫 Score submission rejected: ${validation.reason}`);
            return res.status(403).json({ 
                error: "Score submission rejected", 
                reason: validation.reason 
            });
        }
        
        // ANTI-FARMING: Vérifier la liaison des wallets
        const boundWallet = walletBindings.get(playerAddress);
        
        if (!boundWallet) {
            // Premier mint/evolution: lier les wallets
            walletBindings.set(playerAddress, appKitWallet);
            saveWalletBindings(walletBindings);
            console.log(`[ANTI-FARMING] 🔗 NEW BINDING: Privy ${playerAddress} → AppKit ${appKitWallet}`);
        } else if (boundWallet !== appKitWallet) {
            // Tentative de farming détectée
            console.error(`[ANTI-FARMING] 🚫 FARMING ATTEMPT DETECTED!`);
            console.error(`[ANTI-FARMING] Privy Wallet: ${playerAddress}`);
            console.error(`[ANTI-FARMING] Bound to: ${boundWallet}`);
            console.error(`[ANTI-FARMING] Attempting with: ${appKitWallet}`);
            
            return res.status(403).json({ 
                error: "Wallet farming detected", 
                details: "This Monad Games ID account is bound to a different AppKit wallet"
            });
        } else {
            console.log(`[ANTI-FARMING] ✅ Wallet verified: ${appKitWallet}`);
        }
        
        console.log(`[RPC] Connecting to Alchemy RPC...`);
        const provider = new ethers.providers.JsonRpcProvider('https://monad-testnet.g.alchemy.com/v2/JD1BgcAhWzSNu8vHiT1chCKaHUq3kH6-');
        const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
        
        const MONAD_GAMES_ID_CONTRACT = "0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0";
        const contractABI = [
            "function updatePlayerData(address player, uint256 scoreAmount, uint256 transactionAmount)",
            "function batchUpdatePlayerData(address[] players, uint256[] scoreAmounts, uint256[] transactionAmounts)"
        ];
        
        const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet);
        
        console.log(`[BLOCKCHAIN] Calling updatePlayerData(${playerAddress}, ${scoreAmount}, ${transactionAmount})`);
        
        const nonce = await getNextNonce(wallet);
        console.log(`[BLOCKCHAIN] Using nonce: ${nonce}`);
        
        const tx = await contract.updatePlayerData(playerAddress, scoreAmount, transactionAmount, {
            gasLimit: 150000,
            maxPriorityFeePerGas: ethers.utils.parseUnits('2', 'gwei'),
            maxFeePerGas: ethers.utils.parseUnits('100', 'gwei'),
            nonce: nonce
        });
        
        console.log(`[BLOCKCHAIN] ✅ Transaction sent: ${tx.hash}`);
        console.log(`[BLOCKCHAIN] Waiting for confirmation...`);
        
        const receipt = await tx.wait();
        const duration = Date.now() - startTime;
        
        console.log(`[BLOCKCHAIN] ✅ Transaction confirmed in block ${receipt.blockNumber}`);
        console.log(`[BLOCKCHAIN] Gas used: ${receipt.gasUsed.toString()}`);
        console.log(`[PERFORMANCE] Total request time: ${duration}ms`);
        console.log(`[Monad Games ID] 🎉 SUCCESS - Score submitted for ${playerAddress}`);
        
        res.json({ 
            success: true, 
            transactionHash: tx.hash, 
            blockNumber: receipt.blockNumber, 
            gasUsed: receipt.gasUsed.toString(),
            playerAddress, 
            scoreAmount, 
            transactionAmount, 
            actionType,
            duration: duration,
            message: "Score submitted to Monad Games ID contract"
        });
        
    } catch (error) {
        const duration = Date.now() - startTime;
        console.error(`[Monad Games ID] ❌ ERROR after ${duration}ms:`, error.message);
        console.error(`[Monad Games ID] Stack trace:`, error.stack);
        
        // Log spécifique pour les erreurs RPC
        if (error.message.includes('RPC') || error.message.includes('network')) {
            console.error(`[RPC] Network error detected - check Alchemy connection`);
        }
        
        res.status(500).json({ 
            error: "Failed to submit to Monad Games ID", 
            details: error.message,
            duration: duration
        });
    }
});

// SECURITY: Nouvel endpoint pour validation des scores
app.post('/api/validate-score', requireWallet, async (req, res) => {
    try {
        const { playerAddress, scoreAmount, transactionAmount, matchId, timestamp } = req.body;
        
        console.log(`[SCORE-VALIDATION] 🔍 Validating score for ${playerAddress}: ${scoreAmount}`);
        
        if (!playerAddress || scoreAmount === undefined || transactionAmount === undefined) {
            return res.status(400).json({ error: 'Missing required parameters' });
        }
        
        // Validation de sécurité
        const validation = validateScoreSubmission(playerAddress, scoreAmount, transactionAmount);
        
        if (!validation.valid) {
            console.error(`[SCORE-VALIDATION] 🚫 Validation failed: ${validation.reason}`);
            return res.status(403).json({ 
                valid: false, 
                reason: validation.reason 
            });
        }
        
        // Générer une signature pour valider le score
        const message = ethers.utils.solidityKeccak256(
            ['address', 'uint256', 'uint256', 'uint256', 'string'],
            [playerAddress, scoreAmount, transactionAmount, timestamp || Date.now(), matchId || 'default']
        );
        
        const signature = await gameWallet.signMessage(ethers.utils.arrayify(message));
        
        console.log(`[SCORE-VALIDATION] ✅ Score validated and signed for ${playerAddress}`);
        
        res.json({
            valid: true,
            signature: signature,
            gameServerAddress: gameWallet.address,
            timestamp: Date.now()
        });
        
    } catch (error) {
        console.error('[SCORE-VALIDATION] Error:', error);
        res.status(500).json({ 
            error: "Score validation failed", 
            details: error.message 
        });
    }
});

// BATCH UPDATE: Endpoint pour grouper plusieurs mises à jour (économie de gas)
app.post('/api/monad-games-id/batch-update', requireWallet, async (req, res) => {
    const startTime = Date.now();
    const clientIP = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent');
    
    try {
        // ANTI-BOT: Détection de comportement suspect
        const botCheck = detectBotBehavior(clientIP, userAgent, req);
        if (botCheck.isBot) {
            console.error(`[ANTI-BOT] 🚫 Bot blocked: ${clientIP} - ${botCheck.reason}`);
            return res.status(403).json({ 
                error: "Bot detected", 
                reason: botCheck.reason 
            });
        }
        
        const { updates } = req.body; // Array of {playerAddress, appKitWallet, scoreAmount, transactionAmount, actionType}
        
        console.log(`[BATCH-UPDATE] 🚀 Processing ${updates.length} updates`);
        
        if (!updates || !Array.isArray(updates) || updates.length === 0) {
            return res.status(400).json({ error: 'Updates array required' });
        }
        
        if (updates.length > 50) { // Limite de sécurité
            return res.status(400).json({ error: 'Too many updates (max 50)' });
        }
        
        // Validation de tous les updates
        const validUpdates = [];
        for (const update of updates) {
            const validation = validateScoreSubmission(update.playerAddress, update.scoreAmount, update.transactionAmount);
            if (validation.valid) {
                validUpdates.push(update);
            } else {
                console.warn(`[BATCH-UPDATE] ⚠️ Skipping invalid update: ${validation.reason}`);
            }
        }
        
        if (validUpdates.length === 0) {
            return res.status(400).json({ error: 'No valid updates' });
        }
        
        console.log(`[BATCH-UPDATE] ✅ ${validUpdates.length}/${updates.length} updates valid`);
        
        // Préparer les données pour le batch
        const players = validUpdates.map(u => u.playerAddress);
        const scoreAmounts = validUpdates.map(u => u.scoreAmount);
        const transactionAmounts = validUpdates.map(u => u.transactionAmount);
        
        const provider = new ethers.providers.JsonRpcProvider('https://monad-testnet.g.alchemy.com/v2/JD1BgcAhWzSNu8vHiT1chCKaHUq3kH6-');
        const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
        
        const MONAD_GAMES_ID_CONTRACT = "0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0";
        const contractABI = [
            "function batchUpdatePlayerData(address[] players, uint256[] scoreAmounts, uint256[] transactionAmounts)"
        ];
        
        const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet);
        
        console.log(`[BATCH-UPDATE] Calling batchUpdatePlayerData with ${players.length} players`);
        
        const nonce = await getNextNonce(wallet);
        
        const tx = await contract.batchUpdatePlayerData(players, scoreAmounts, transactionAmounts, {
            gasLimit: 500000, // Plus de gas pour le batch
            maxPriorityFeePerGas: ethers.utils.parseUnits('2', 'gwei'),
            maxFeePerGas: ethers.utils.parseUnits('100', 'gwei'),
            nonce: nonce
        });
        
        console.log(`[BATCH-UPDATE] ✅ Transaction sent: ${tx.hash}`);
        
        const receipt = await tx.wait();
        const duration = Date.now() - startTime;
        
        console.log(`[BATCH-UPDATE] ✅ Transaction confirmed in block ${receipt.blockNumber}`);
        console.log(`[BATCH-UPDATE] Gas used: ${receipt.gasUsed.toString()}`);
        console.log(`[BATCH-UPDATE] 🎉 SUCCESS - ${players.length} players updated in batch`);
        
        res.json({ 
            success: true, 
            transactionHash: tx.hash, 
            blockNumber: receipt.blockNumber, 
            gasUsed: receipt.gasUsed.toString(),
            playersUpdated: players.length,
            duration: duration,
            message: "Batch update completed successfully"
        });
        
    } catch (error) {
        const duration = Date.now() - startTime;
        console.error(`[BATCH-UPDATE] ❌ ERROR after ${duration}ms:`, error.message);
        res.status(500).json({ 
            error: "Batch update failed", 
            details: error.message,
            duration: duration
        });
    }
});

// ===== FIREBASE SCORE VALIDATION ENDPOINT =====
// Endpoint sécurisé pour valider et soumettre les scores Firebase
app.post('/api/firebase/submit-score', requireWallet, async (req, res) => {
    const startTime = Date.now();
    
    try {
        const { walletAddress, score, bonus, matchId, matchToken } = req.body;
        // Vérification Firebase ID token (Authorization: Bearer ...)
        const uid = await verifyFirebaseIdTokenFromRequest(req);
        if (!uid) return res.status(401).json({ error: 'Invalid or missing Firebase ID token' });
        
        console.log(`[FIREBASE-SCORE] 📊 Score submission request from ${walletAddress}`);
        console.log(`[FIREBASE-SCORE] Score: ${score}, Bonus: ${bonus}, Match: ${matchId}`);
        
        // Validation des paramètres
        if (!walletAddress || score === undefined || !matchId) {
            return res.status(400).json({ 
                error: 'Missing required parameters: walletAddress, score, matchId' 
            });
        }
        
        // Validation de l'adresse wallet
        if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
            return res.status(400).json({ 
                error: 'Invalid wallet address format' 
            });
        }
        
        const normalizedAddress = walletAddress.toLowerCase();
        const totalScore = parseInt(score) + (parseInt(bonus) || 0);
        
        // Validation du score (anti-triche de base)
        if (totalScore < 0 || totalScore > 1000) {
            console.warn(`[FIREBASE-SCORE] ⚠️ Score suspect: ${totalScore} from ${normalizedAddress}`);
            return res.status(403).json({ 
                error: 'Score out of reasonable range (0-1000)' 
            });
        }

        // Vérification matchToken (empêche soumissions hors gameplay)
        if (!matchToken) {
            return res.status(401).json({ error: 'Missing matchToken' });
        }
        const mt = matchTokens.get(matchToken);
        if (!mt) {
            return res.status(401).json({ error: 'Invalid matchToken' });
        }
        if (mt.uid !== uid) {
            return res.status(401).json({ error: 'MatchToken uid mismatch' });
        }
        if (mt.used || Date.now() > mt.expMs) {
            matchTokens.delete(matchToken);
            return res.status(401).json({ error: 'Expired or used matchToken' });
        }
        // Marquer comme utilisé (un submit par matchToken)
        mt.used = true;
        matchTokens.set(matchToken, mt);
        
        // Rate limiting spécifique aux scores (par uid, pas par wallet)
        const scoreKey = `score_uid_${uid}`;
        const now = Date.now();
        
        if (!scoreRateLimit.has(scoreKey)) {
            scoreRateLimit.set(scoreKey, { count: 1, resetTime: now + 60000 });
        } else {
            const data = scoreRateLimit.get(scoreKey);
            if (now < data.resetTime) {
                if (data.count >= 10) { // 10 scores par minute max
                    return res.status(429).json({ 
                        error: 'Too many score submissions, please wait' 
                    });
                }
                data.count++;
            } else {
                scoreRateLimit.set(scoreKey, { count: 1, resetTime: now + 60000 });
            }
        }
        
        // Vérifier l'intervalle minimum entre soumissions (par uid)
        const lastSubmission = lastScoreSubmission.get(uid);
        if (lastSubmission && (now - lastSubmission) < 5000) { // 5 secondes minimum
            return res.status(429).json({ 
                error: 'Please wait before submitting another score' 
            });
        }
        
        lastScoreSubmission.set(uid, now);
        
        // Vérifier si Firebase Admin est disponible
        if (!admin.apps.length) {
            console.error('[FIREBASE-SCORE] ❌ Firebase Admin not initialized');
            return res.status(503).json({ 
                error: 'Score validation service unavailable' 
            });
        }
        
        // Écriture sécurisée dans Firebase via Admin SDK avec idempotence uid+matchId
        const db = admin.firestore();
        const docRef = db.collection('WalletScores').doc(normalizedAddress);
        const markerId = `${uid}:${matchId}`;
        const markerRef = db.collection('ProcessedSubmissions').doc(markerId);
        
        await db.runTransaction(async (transaction) => {
            const marker = await transaction.get(markerRef);
            if (marker.exists) {
                throw Object.assign(new Error('Duplicate submission'), { code: 409 });
            }
            const doc = await transaction.get(docRef);
            
            if (!doc.exists) {
                // Nouveau joueur
                transaction.set(docRef, {
                    score: totalScore,
                    nftLevel: 0,
                    walletAddress: normalizedAddress,
                    uid: uid,
                    lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
                    createdAt: admin.firestore.FieldValue.serverTimestamp(),
                    matchId: matchId,
                    validatedBy: 'server',
                    serverSignature: await gameWallet.signMessage(
                        ethers.utils.arrayify(
                            ethers.utils.solidityKeccak256(
                                ['address', 'uint256', 'string'],
                                [normalizedAddress, totalScore, matchId]
                            )
                        )
                    )
                });
                
                console.log(`[FIREBASE-SCORE] ✅ Nouveau joueur créé: ${normalizedAddress} avec score: ${totalScore}`);
            } else {
                // Joueur existant - addition des scores
                const currentData = doc.data();
                const currentScore = Number(currentData.score || 0);
                const newScore = currentScore + totalScore;
                
                transaction.update(docRef, {
                    score: newScore,
                    walletAddress: normalizedAddress,
                    uid: uid,
                    lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
                    matchId: matchId,
                    validatedBy: 'server',
                    serverSignature: await gameWallet.signMessage(
                        ethers.utils.arrayify(
                            ethers.utils.solidityKeccak256(
                                ['address', 'uint256', 'string'],
                                [normalizedAddress, newScore, matchId]
                            )
                        )
                    )
                });
                
                console.log(`[FIREBASE-SCORE] ✅ Score mis à jour: ${currentScore} + ${totalScore} = ${newScore}`);
            }
            transaction.set(markerRef, {
                uid: uid,
                walletAddress: normalizedAddress,
                matchId: matchId,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                scoreSubmitted: totalScore
            });
        });
        
        const duration = Date.now() - startTime;
        console.log(`[FIREBASE-SCORE] 🎉 Score validé et soumis en ${duration}ms`);
        
        res.json({
            success: true,
            walletAddress: normalizedAddress,
            score: totalScore,
            matchId: matchId,
            validated: true,
            duration: duration,
            message: "Score validated and submitted securely"
        });
        
    } catch (error) {
        console.error('[FIREBASE-SCORE] ❌ Error:', error);
        res.status(500).json({ 
            error: "Failed to validate and submit score", 
            details: error.message 
        });
    }
});

app.listen(port, () => {
    console.log(`🚀 ==========================================`);
    console.log(`🚀 CHOGTANKS SIGNATURE SERVER STARTED`);
    console.log(`🚀 ==========================================`);
    console.log(`🚀 Port: ${port}`);
    console.log(`🚀 Game Server Address: ${gameWallet ? gameWallet.address : 'N/A (no private key)'}`);
    console.log(`🚀 RPC: Alchemy Monad Testnet`);
    console.log(`🚀 Contract: 0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0`);
    console.log(`🚀 Anti-farming: ${walletBindings.size} bindings loaded`);
    console.log(`🚀 Uptime: ${new Date().toISOString()}`);
    console.log(`🚀 ==========================================`);
});

// Garde-fous contre les crashs silencieux
process.on('unhandledRejection', (reason) => {
    console.error('[unhandledRejection]', reason);
});
process.on('uncaughtException', (err) => {
    console.error('[uncaughtException]', err);
});
