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

// Middleware: Auth Firebase obligatoire si FIREBASE_REQUIRE_AUTH === '1'
async function requireFirebaseAuth(req, res, next) {
    try {
        if (process.env.FIREBASE_REQUIRE_AUTH !== '1') {
            return next();
        }

        const auth = req.headers.authorization || '';
        if (!auth.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing token' });
        }

        const token = auth.slice(7);

        // Initialiser Firebase Admin si nécessaire
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

        const decoded = await require('firebase-admin').auth().verifyIdToken(token);
        if (!decoded || !decoded.uid) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        // Optionnel: attacher l'utilisateur Firebase à la requête
        req.firebaseUser = decoded;
        return next();
    } catch (err) {
        console.error('[AUTH] Firebase verification failed:', err?.message || err);
        return res.status(401).json({ error: 'Unauthorized' });
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

// Compat ancien build: soumission de score (admin côté serveur)
app.post('/api/firebase/submit-score', requireWallet, async (req, res) => {
    try {
        const { walletAddress, score, bonus, matchId } = req.body || {};
        if (!walletAddress || typeof score === 'undefined') {
            return res.status(400).json({ error: 'Missing walletAddress or score' });
        }
        if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
            return res.status(400).json({ error: 'Invalid wallet address format' });
        }

        const normalized = walletAddress.toLowerCase();
        const totalScore = (parseInt(score, 10) || 0) + (parseInt(bonus, 10) || 0);
        console.log(`[SUBMIT-SCORE] Score submitted for ${normalized}: ${totalScore} (base: ${score}, bonus: ${bonus})`);

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
                const doc = await docRef.get();
                let currentScore = 0;
                if (doc.exists) currentScore = Number(doc.data().score || 0);
                const newTotalScore = currentScore + totalScore;

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
                // Fallback: accepter pour compat
                return res.json({ success: true, walletAddress: normalized, score: totalScore, matchId: matchId || 'legacy', validated: true });
            }
        } else {
            console.warn('[SUBMIT-SCORE] Firebase non configuré - score accepté mais non sauvegardé');
            return res.json({ success: true, walletAddress: normalized, score: totalScore, matchId: matchId || 'legacy', validated: true });
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
        
        const nonce = Date.now();
        const playerPoints = 0; // Pour le mint, on utilise 0 points comme dans le contrat
        
        // Signature attendue par le contrat:
        // keccak256(abi.encodePacked(msg.sender, playerPoints, nonce, "MINT")).toEthSignedMessageHash()
        const messageHash = ethers.utils.solidityKeccak256(
            ['address', 'uint256', 'uint256', 'string'],
            [playerAddress, playerPoints, nonce, 'MINT']
        );
        
        // Convertir en format EIP-191 comme fait le contrat avec toEthSignedMessageHash()
        const ethSignedMessageHash = ethers.utils.hashMessage(ethers.utils.arrayify(messageHash));
        const signature = await gameWallet.signMessage(ethers.utils.arrayify(messageHash));
        
        console.log(`[MINT] ✅ Autorisation de mint générée pour ${playerAddress} avec un coût de ${mintCost}`);
        console.log(`[MONITORING] 🎯 MINT REQUEST - Wallet: ${playerAddress}, Cost: ${mintCost}, Nonce: ${nonce}, Timestamp: ${new Date().toISOString()}`);
        
        res.json({
            signature: signature,
            mintCost: mintCost,
            nonce: nonce,
            authorized: true,
            gameServerAddress: gameWallet.address
        });
        
    } catch (error) {
        console.error('Erreur d\'autorisation de mint:', error);
        res.status(500).json({ error: "Erreur interne du serveur" });
    }
});

app.post('/api/evolve-authorization', requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const { playerAddress, tokenId, targetLevel, playerPoints } = req.body;
        
        if (!playerAddress || tokenId === undefined || targetLevel === undefined) {
            return res.status(400).json({ error: "Paramètres manquants (playerAddress, tokenId, targetLevel)" });
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
        
        // Optionnel: vérifier on-chain pour dériver le niveau courant et la propriété
        let numericTokenId = Number(tokenId);
        let numericTargetLevel = Number(targetLevel);
        let requiredPoints = evolutionCosts[numericTargetLevel];

        try {
            const provider = new ethers.providers.JsonRpcProvider('https://testnet-rpc.monad.xyz/');
            const contractAddress = '0x04223adab3a0c1a2e8aade678bebd3fddd580a38';
            const abi = [
                'function ownerOf(uint256 tokenId) view returns (address)',
                'function getLevel(uint256 tokenId) view returns (uint256)'
            ];
            const contract = new ethers.Contract(contractAddress, abi, provider);
            const owner = await contract.ownerOf(numericTokenId);
            if (owner.toLowerCase() !== playerAddress.toLowerCase()) {
                return res.status(403).json({ error: 'Not your NFT' });
            }
            const onchainLevel = Number(await contract.getLevel(numericTokenId));
            // Calculer target à partir de l'état on-chain pour éviter toute dérive client
            numericTargetLevel = onchainLevel + 1;
            requiredPoints = evolutionCosts[numericTargetLevel];
        } catch (chainErr) {
            console.warn('[EVOLVE] On-chain read failed, using client-provided targetLevel:', chainErr?.message || chainErr);
        }
        
        if (!requiredPoints) {
            return res.status(400).json({ error: "Niveau cible invalide" });
        }
        const pointsForSig = Number(playerPoints);
        const nonce = Date.now();

        // Signature attendue par le contrat:
        // keccak256(abi.encodePacked(msg.sender, tokenId, targetLevel, playerPoints, nonce, "EVOLVE"))
        const message = ethers.utils.solidityKeccak256(
            ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'string'],
            [playerAddress, numericTokenId, numericTargetLevel, pointsForSig, nonce, 'EVOLVE']
        );
        const signature = await gameWallet.signMessage(ethers.utils.arrayify(message));
        
        console.log(`[EVOLVE] ✅ Autorisation d'évolution générée pour ${playerAddress}, token ${numericTokenId} vers niveau ${numericTargetLevel}`);
        console.log(`[MONITORING] 🚀 EVOLVE REQUEST - Wallet: ${playerAddress}, Token: ${numericTokenId}, Target Level: ${numericTargetLevel}, Cost: ${requiredPoints}, Timestamp: ${new Date().toISOString()}`);
        
        res.json({
            authorized: true,
            walletAddress: playerAddress,
            tokenId: numericTokenId,
            evolutionCost: requiredPoints,
            targetLevel: numericTargetLevel,
            nonce: nonce,
            signature: signature
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
        
        const provider = new ethers.providers.JsonRpcProvider('https://testnet-rpc.monad.xyz/');
        const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
        
        const MONAD_GAMES_ID_CONTRACT = "0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0";
        const contractABI = [
            "function updatePlayerData(address player, uint256 scoreAmount, uint256 transactionAmount)"
        ];
        
        const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet);
        
        console.log(`[Monad Games ID] Calling updatePlayerData(${playerAddress}, ${scoreAmount}, ${transactionAmount})`);
        
        const nonce = await getNextNonce(wallet);
        
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

// Endpoint sécurisé: consommer les points après évolution (mise à jour Firebase côté serveur)
app.post('/api/consume-evolution-points', requireWallet, requireFirebaseAuth, async (req, res) => {
    try {
        const { walletAddress, pointsToConsume, tokenId, newLevel } = req.body || {};
        
        if (!walletAddress || pointsToConsume === undefined || !tokenId || !newLevel) {
            return res.status(400).json({ error: "Paramètres manquants" });
        }
        
        const normalized = walletAddress.toLowerCase().trim();
        
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
                
                // Lire le score actuel
                const docRef = db.collection('WalletScores').doc(normalized);
                const doc = await docRef.get();
                
                if (!doc.exists) {
                    return res.status(404).json({ error: "Joueur non trouvé" });
                }
                
                const currentScore = Number(doc.data().score || 0);
                const newScore = Math.max(0, currentScore - Number(pointsToConsume));
                
                // Mettre à jour le score et le niveau
                await docRef.set({
                    score: newScore,
                    nftLevel: Number(newLevel),
                    tokenId: Number(tokenId),
                    lastUpdated: require('firebase-admin').firestore.FieldValue.serverTimestamp(),
                    lastEvolutionTimestamp: require('firebase-admin').firestore.FieldValue.serverTimestamp()
                }, { merge: true });
                
                console.log(`[CONSUME-POINTS] ✅ ${currentScore} - ${pointsToConsume} = ${newScore}`);
                console.log(`[MONITORING] 🔥 POINTS CONSUMED - Wallet: ${normalized}, Points: ${pointsToConsume}, New Score: ${newScore}, Token: ${tokenId}, Level: ${newLevel}, Timestamp: ${new Date().toISOString()}`);
                
                return res.json({
                    success: true,
                    consumedPoints: Number(pointsToConsume),
                    newScore: newScore,
                    walletAddress: normalized
                });
                
            } catch (firebaseError) {
                console.error('[CONSUME-POINTS] Erreur Firebase:', firebaseError);
                return res.status(500).json({ error: "Erreur Firebase" });
            }
        } else {
            console.warn('[CONSUME-POINTS] Firebase non configuré');
            return res.status(503).json({ error: 'Firebase non configuré côté serveur' });
        }
        
    } catch (error) {
        console.error('[CONSUME-POINTS] Erreur:', error);
        res.status(500).json({ error: "Erreur serveur" });
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
