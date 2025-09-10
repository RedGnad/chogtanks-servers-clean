const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
require('dotenv').config();

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

app.post('/api/monad-games-id/update-player', rateLimit, requireWallet, async (req, res) => {
    enqueueTx(async () => {
        try {
            const { playerAddress, appKitWallet, scoreAmount, transactionAmount, actionType } = req.body;
            if (!playerAddress || !appKitWallet || scoreAmount === undefined || transactionAmount === undefined) {
                return res.status(400).json({ error: 'Missing required parameters' });
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
            if (!res.headersSent) res.json({ success: true, transactionHash: tx.hash, blockNumber: receipt.blockNumber, playerAddress, scoreAmount, transactionAmount, actionType });
        } catch (error) {
            console.error('[UPDATE] Error:', error.message);
            if (!res.headersSent) res.status(500).json({ error: 'Failed to submit', details: error.message });
        }
    }, res);
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
