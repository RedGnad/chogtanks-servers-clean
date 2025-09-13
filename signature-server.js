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

// CORS restrictif (configurable par ALLOWED_ORIGINS)
const defaultAllowed = [
    'https://redgnad.github.io',
    'https://chogtanks.vercel.app',
    'https://monadclip.io'
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
                // Fallback: accepter le score même si Firebase échoue
                return res.json({
                    success: true,
                    walletAddress: normalized,
                    score: totalScore,
                    matchId: matchId || 'legacy',
                    validated: true
                });
            }
        } else {
            console.warn('[SUBMIT-SCORE] Firebase non configuré - score accepté mais non sauvegardé');
            return res.json({
                success: true,
                walletAddress: normalized,
                score: totalScore,
                matchId: matchId || 'legacy',
                validated: true
            });
        }
    } catch (error) {
        console.error('[SUBMIT-SCORE] Error:', error);
        res.status(500).json({ error: 'Failed to submit score', details: error.message });
    }
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
        
        console.log(`[MINT] ✅ Autorisation de mint générée pour ${playerAddress} avec un coût de ${mintCost}`);
        console.log(`[MONITORING] 🎯 MINT REQUEST - Wallet: ${playerAddress}, Cost: ${mintCost}, Timestamp: ${new Date().toISOString()}`);
        
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
        const { playerAddress, tokenId, targetLevel } = req.body;
        
        if (!playerAddress || !tokenId || !targetLevel) {
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
        
        const message = ethers.utils.solidityKeccak256(
            ['address', 'uint256', 'uint256', 'uint256'],
            [playerAddress, tokenId, targetLevel, requiredPoints]
        );
        
    const signature = await gameWallet.signMessage(ethers.utils.arrayify(message));
        
        console.log(`[EVOLVE] ✅ Autorisation d'évolution générée pour ${playerAddress}, token ${tokenId} vers niveau ${targetLevel}`);
        console.log(`[MONITORING] 🚀 EVOLVE REQUEST - Wallet: ${playerAddress}, Token: ${tokenId}, Target Level: ${targetLevel}, Cost: ${requiredPoints}, Timestamp: ${new Date().toISOString()}`);
        
        res.json({
            authorized: true,
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

// =====================
// Monad Games ID - BATCH
// =====================
const ENABLE_MONAD_BATCH = process.env.ENABLE_MONAD_BATCH === '1';
const BATCH_FLUSH_MS = Number(process.env.BATCH_FLUSH_MS || 1500); // 1.5s
const BATCH_MAX = Number(process.env.BATCH_MAX || 100);
const BATCH_MAX_WAIT_MS = Number(process.env.BATCH_MAX_WAIT_MS || 3000);

// Queue en mémoire: agrégation par joueur
// Structure: Map<address, { score: number, tx: number, firstAt: number }>
const batchQueue = new Map();
let isFlushing = false;
let lastFlushAt = Date.now();

function enqueuePlayerUpdate(player, scoreDelta, txDelta) {
    const key = player.toLowerCase();
    const prev = batchQueue.get(key) || { score: 0, tx: 0, firstAt: Date.now() };
    prev.score = Number(prev.score) + Number(scoreDelta || 0);
    prev.tx = Number(prev.tx) + Number(txDelta || 0);
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
            const receipt = await tx.wait();
            console.log(`[Monad Games ID][BATCH] Confirmed in block ${receipt.blockNumber} (gasUsed=${receipt.gasUsed.toString()})`);

            // Retirer du buffer les entrées confirmées
            for (const [addr] of chunk) {
                batchQueue.delete(addr);
            }
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
        const { playerAddress, appKitWallet, scoreAmount, transactionAmount, actionType } = req.body;
        
        if (!playerAddress || !appKitWallet || scoreAmount === undefined || transactionAmount === undefined) {
            return res.status(400).json({ error: 'Missing required parameters' });
        }
        
        console.log(`[Monad Games ID] Received request: ${actionType} for ${playerAddress}`);
        console.log(`[Monad Games ID] Score: ${scoreAmount}, Transactions: ${transactionAmount}`);
        console.log(`[Monad Games ID] AppKit wallet: ${appKitWallet}`);
        
        // ANTI-FARMING: Vérifier la liaison des wallets
        const boundWallet = walletBindings.get(playerAddress);
        
        if (!boundWallet) {
            // Premier mint/evolution: lier les wallets
            walletBindings.set(playerAddress, appKitWallet);
            saveWalletBindings(walletBindings);
            console.log(`[ANTI-FARMING] 🔗 Liaison créée et sauvegardée: Privy ${playerAddress} → AppKit ${appKitWallet}`);
        } else if (boundWallet !== appKitWallet) {
            // Tentative de farming détectée
            console.error(`[ANTI-FARMING] 🚫 FARMING DÉTECTÉ!`);
            console.error(`[ANTI-FARMING] Privy: ${playerAddress}`);
            console.error(`[ANTI-FARMING] Wallet lié: ${boundWallet}`);
            console.error(`[ANTI-FARMING] Wallet actuel: ${appKitWallet}`);
            
            return res.status(403).json({ 
                error: "Wallet farming detected", 
                details: "This Monad Games ID account is bound to a different AppKit wallet"
            });
        } else {
            console.log(`[ANTI-FARMING] ✅ Wallet vérifié: ${appKitWallet}`);
        }
        
        if (ENABLE_MONAD_BATCH) {
            enqueuePlayerUpdate(playerAddress, scoreAmount, transactionAmount);
            // Feedback immédiat pour l'UX
            return res.json({ 
                success: true, 
                queued: true,
                playerAddress,
                scoreAmount,
                transactionAmount,
                actionType
            });
        } else {
            const rpcUrl = process.env.MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz/';
            const provider = new ethers.providers.JsonRpcProvider(rpcUrl);
            const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
            const MONAD_GAMES_ID_CONTRACT = '0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0';
            const contractABI = [
                'function updatePlayerData(address player, uint256 scoreAmount, uint256 transactionAmount)'
            ];
            const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet);

            console.log(`[Monad Games ID] Calling updatePlayerData(${playerAddress}, ${scoreAmount}, ${transactionAmount})`);
            const nonce = await getNextNonce(wallet);
            const tx = await contract.updatePlayerData(playerAddress, scoreAmount, transactionAmount, {
                gasLimit: 150000,
                maxPriorityFeePerGas: ethers.utils.parseUnits('2', 'gwei'),
                maxFeePerGas: ethers.utils.parseUnits('100', 'gwei'),
                nonce
            });
            console.log(`[Monad Games ID] Transaction sent: ${tx.hash}`);
            const receipt = await tx.wait();
            console.log(`[Monad Games ID] Transaction confirmed in block ${receipt.blockNumber}`);
            console.log(`[Monad Games ID] Gas used: ${receipt.gasUsed.toString()}`);
            
            return res.json({ 
                success: true, 
                transactionHash: tx.hash, 
                blockNumber: receipt.blockNumber, 
                gasUsed: receipt.gasUsed.toString(),
                playerAddress, 
                scoreAmount, 
                transactionAmount, 
                actionType,
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
