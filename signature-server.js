const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

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
    try {
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
            "function updatePlayerData(address player, uint256 scoreAmount, uint256 transactionAmount)"
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
