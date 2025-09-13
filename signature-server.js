const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const admin = require('firebase-admin');

const app = express();
app.use(express.json());
app.use(cors());

// ===== METRICS LÉGÈRES EN MÉMOIRE =====
const metrics = {
    authSuccess: 0,
    authFailure: 0,
    mintRequests: 0,
    evolveRequests: 0,
    onchainInternalCalls: 0,
    onchainForbidden: 0,
    onchainDryRuns: 0,
    firebaseSubmit: 0,
    firebaseRead: 0
};

const port = process.env.PORT || 3001;

// ===== FIREBASE ADMIN SDK =====
if (!admin.apps.length) {
    try {
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
        console.log('[FIREBASE] ✅ Admin SDK initialisé');
    } catch (e) {
        console.warn('[FIREBASE] ⚠️ Admin SDK non initialisé:', e.message);
    }
}

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

// ===== Auth Firebase (ID token) =====
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

async function requireFirebaseAuth(req, res, next) {
    const hasAuth = Boolean((req.headers['authorization'] || '').startsWith('Bearer '));
    console.log(`[AUTH] Authorization header present: ${hasAuth}`);
    const uid = await verifyFirebaseIdTokenFromRequest(req);
    if (!uid) {
        console.warn('[AUTH] ❌ Firebase ID token invalid or missing');
        metrics.authFailure++;
        return res.status(401).json({ error: 'Unauthorized' });
    }
    req.uid = uid;
    console.log(`[AUTH] ✅ Firebase UID resolved: ${uid}`);
    metrics.authSuccess++;
    next();
}

// Vérifie que le wallet appartient au UID (Firestore WalletScores)
async function assertWalletBelongsToUid(walletAddress, uid) {
    if (!admin.apps.length) {
        console.warn('[AUTH] ⚠️ Firebase Admin not initialized, cannot verify wallet ownership');
        return { ok: false, reason: 'admin_not_initialized' };
    }
    if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress || '')) {
        return { ok: false, reason: 'invalid_wallet' };
    }
    const db = admin.firestore();
    const normalized = walletAddress.toLowerCase();
    const docRef = db.collection('WalletScores').doc(normalized);
    const doc = await docRef.get();
    if (!doc.exists) {
        console.warn(`[AUTH] ❌ Wallet not linked in WalletScores: ${walletAddress}`);
        return { ok: false, reason: 'wallet_not_linked' };
    }
    const data = doc.data() || {};
    if (data.uid !== uid) {
        console.warn(`[AUTH] ❌ UID mismatch for wallet ${walletAddress} (expected ${data.uid}, got ${uid})`);
        return { ok: false, reason: 'uid_mismatch' };
    }
    return { ok: true };
}

// ===== Header interne requis pour appels on-chain =====
function requireInternalJob(req, res, next) {
    const header = req.headers['x-internal-job'];
    const secret = process.env.INTERNAL_JOB_SECRET;
    if (!secret) {
        console.error('[SECURITY] INTERNAL_JOB_SECRET non défini');
        return res.status(503).json({ error: 'Server misconfigured' });
    }
    const ok = typeof header === 'string' && header === secret;
    console.log(`[SECURITY] Internal job header valid: ${ok}`);
    if (!ok) {
        metrics.onchainForbidden++;
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

// Health check endpoint pour monitoring
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        version: '2.0.0',
        walletReady: Boolean(gameWallet),
        dryRunOnchain: process.env.DRY_RUN_ONCHAIN === 'true'
    });
});
// Supporte aussi la méthode HEAD sur /health
app.head('/health', (req, res) => res.sendStatus(200));

// ===== FIREBASE SCORE READ ENDPOINT =====
// Lecture sécurisée du score (serveur -> Firestore via Admin SDK)
app.get('/api/firebase/get-score/:walletAddress', requireWallet, async (req, res) => {
  try {
    const { walletAddress } = req.params;
    if (!walletAddress || !/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
      return res.status(400).json({ error: 'Invalid wallet address format' });
    }

    if (!admin.apps.length) {
      return res.status(503).json({ error: 'Score read service unavailable' });
    }

    const normalizedAddress = walletAddress.toLowerCase();
    const db = admin.firestore();
    const docRef = db.collection('WalletScores').doc(normalizedAddress);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.json({ walletAddress: normalizedAddress, score: 0, nftLevel: 0, isNew: true });
    }

    const data = doc.data();
    const score = Number(data.score || 0);
    const nftLevel = Number(data.nftLevel || 0);
    // Metrics
    if (typeof metrics !== 'undefined') { metrics.firebaseRead++; }
    return res.json({ walletAddress: normalizedAddress, score, nftLevel, isNew: false });
  } catch (error) {
    console.error('[FIREBASE-READ] ❌ Error:', error);
    res.status(500).json({ error: 'Failed to read score', details: error.message });
  }
});

// ===== FIREBASE SCORE SUBMIT ENDPOINT =====
// Soumission sécurisée du score depuis le client (auth Firebase requise)
app.post('/api/firebase/submit-score', requireWallet, requireFirebaseAuth, async (req, res) => {
  try {
    const { walletAddress, score, bonus, matchId } = req.body || {};
    if (!walletAddress || typeof score === 'undefined' || !matchId) {
      return res.status(400).json({ error: 'Missing required parameters: walletAddress, score, matchId' });
    }
    if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
      return res.status(400).json({ error: 'Invalid wallet address format' });
    }
    const normalized = walletAddress.toLowerCase();
    const totalScore = (parseInt(score, 10) || 0) + (parseInt(bonus, 10) || 0);
    if (totalScore < 0 || totalScore > 1000) {
      return res.status(403).json({ error: 'Score out of reasonable range (0-1000)' });
    }

    if (!admin.apps.length) {
      return res.status(503).json({ error: 'Score submit service unavailable' });
    }

    const db = admin.firestore();
    const docRef = db.collection('WalletScores').doc(normalized);
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(docRef);
      if (!snap.exists) {
        tx.set(docRef, {
          score: totalScore,
          nftLevel: 0,
          walletAddress: normalized,
          uid: req.uid,
          lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          matchId: matchId,
          validatedBy: 'server'
        });
      } else {
        const data = snap.data() || {};
        const currentScore = Number(data.score || 0);
        tx.update(docRef, {
          score: currentScore + totalScore,
          walletAddress: normalized,
          uid: req.uid,
          lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
          matchId: matchId,
          validatedBy: 'server'
        });
      }
    });

    if (typeof metrics !== 'undefined') { metrics.firebaseSubmit++; }
    return res.json({ success: true, walletAddress: normalized, score: totalScore, matchId });
  } catch (error) {
    console.error('[FIREBASE-SUBMIT] ❌ Error:', error);
    res.status(500).json({ error: 'Failed to submit score', details: error.message });
  }
});

// Expose métriques légères
app.get('/metrics-lite', (req, res) => {
    res.status(200).json({ metrics });
});

app.post('/api/mint-authorization', requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const playerAddress = req.body.playerAddress || req.body.walletAddress;
        let { mintCost } = req.body;
        
        console.log(`[MINT-AUTH] Request by uid=${req.uid}, player=${playerAddress}, cost=${mintCost}`);
        metrics.mintRequests++;

        if (!playerAddress) {
            return res.status(400).json({ error: "Adresse du joueur requise" });
        }

        const ownership = await assertWalletBelongsToUid(playerAddress, req.uid);
        if (!ownership.ok) {
            return res.status(403).json({ error: 'Wallet not linked to user', reason: ownership.reason });
        }
        
        // Déterminer le coût de mint côté serveur si non fourni
        const defaultMintCostWei = process.env.DEFAULT_MINT_COST_WEI || '1000000000000000';
        try {
            mintCost = mintCost ?? defaultMintCostWei;
            // Valider format (BigNumber parsable)
            ethers.BigNumber.from(mintCost);
        } catch {
            return res.status(400).json({ error: 'Invalid mintCost format' });
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
        // COMPATIBILITÉ: Accepter ancien format (walletAddress) ET nouveau (playerAddress)
        const playerAddress = req.body.playerAddress || req.body.walletAddress;
        const tokenId = Number(req.body.tokenId || req.body.tokenID || 0);
        const targetLevel = Number(req.body.targetLevel || req.body.level || 0);
        
        console.log(`[EVOLVE-AUTH] Request body:`, req.body);
        console.log(`[EVOLVE-AUTH] Parsed -> player=${playerAddress}, tokenId=${tokenId}, targetLevel=${targetLevel}`);
        metrics.evolveRequests++;

        if (!playerAddress || !tokenId || !targetLevel) {
            return res.status(400).json({ error: "Adresse du joueur, ID du token et niveau cible requis" });
        }

        // AUTH FIREBASE OPTIONNELLE pour compatibilité ancien build
        const authHeader = req.headers['authorization'] || '';
        const hasFirebaseAuth = authHeader.startsWith('Bearer ');
        console.log(`[EVOLVE-AUTH] Firebase auth present: ${hasFirebaseAuth}`);
        
        if (hasFirebaseAuth) {
            const uid = await verifyFirebaseIdTokenFromRequest(req);
            if (uid) {
                req.uid = uid;
                const ownership = await assertWalletBelongsToUid(playerAddress, uid);
                if (!ownership.ok) {
                    console.warn(`[EVOLVE-AUTH] Wallet ownership check failed: ${ownership.reason}`);
                    // Continue sans bloquer pour compatibilité
                }
            }
        }
        
        // COÛTS ÉTENDUS (inclut niveau 5 = 300 points)
        const evolutionCosts = {
            1: 50,   // Level 0 -> 1
            2: 100,  // Level 1 -> 2
            3: 150,  // Level 2 -> 3
            4: 200,  // Level 3 -> 4
            5: 300   // Level 4 -> 5 (NOUVEAU)
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
        
        console.log(`Autorisation d'évolution générée pour ${playerAddress}, token ${tokenId} vers niveau ${targetLevel} (${requiredPoints} points)`);
        
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
// (fs/path déjà importés en haut)

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

app.post('/api/monad-games-id/update-player', requireWallet, requireInternalJob, async (req, res) => {
    try {
        const { playerAddress, appKitWallet, scoreAmount, transactionAmount, actionType } = req.body;
        
        if (!playerAddress || !appKitWallet || scoreAmount === undefined || transactionAmount === undefined) {
            return res.status(400).json({ error: 'Missing required parameters' });
        }
        
        console.log(`[Monad Games ID] 🔐 Internal call received for ${playerAddress}`);
        metrics.onchainInternalCalls++;
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
        
        const rpcUrl = process.env.ALCHEMY_RPC_URL;
        if (!rpcUrl) {
            console.error('[RPC] ❌ ALCHEMY_RPC_URL manquante');
        }
        const provider = new ethers.providers.JsonRpcProvider(rpcUrl);
        const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
        
        const MONAD_GAMES_ID_CONTRACT = "0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0";
        const contractABI = [
            "function updatePlayerData(address player, uint256 scoreAmount, uint256 transactionAmount)"
        ];
        
        const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet);
        
        console.log(`[Monad Games ID] Calling updatePlayerData(${playerAddress}, ${scoreAmount}, ${transactionAmount})`);
        
        const nonce = await getNextNonce(wallet);

        if (process.env.DRY_RUN_ONCHAIN === 'true') {
            metrics.onchainDryRuns++;
            console.log(`[BLOCKCHAIN-DRYRUN] updatePlayerData(${playerAddress}, ${scoreAmount}, ${transactionAmount})`);
            return res.json({ success: true, dryRun: true, playerAddress, scoreAmount, transactionAmount });
        }

        const tx = await contract.updatePlayerData(playerAddress, scoreAmount, transactionAmount, {
            gasLimit: 150000, // Augmenté pour plus de sécurité
            maxPriorityFeePerGas: ethers.utils.parseUnits('2', 'gwei'), // 2 gwei priority fee
            maxFeePerGas: ethers.utils.parseUnits('100', 'gwei'), // 100 gwei pour être sûr d'être inclus
            nonce: nonce
        });
        
        console.log(`[Monad Games ID] Transaction sent: ${tx.hash}`);
        
        const receipt = await tx.wait();
        console.log(`[Monad Games ID] Transaction confirmed in block ${receipt.blockNumber}`);
        console.log(`[Monad Games ID] Gas used: ${receipt.gasUsed.toString()}`);
        
        res.json({ 
            success: true, 
            transactionHash: tx.hash, 
            blockNumber: receipt.blockNumber, 
            gasUsed: receipt.gasUsed.toString(),
            playerAddress, 
            scoreAmount, 
            transactionAmount, 
            actionType,
            message: "Score submitted to Monad Games ID contract"
        });
        
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
