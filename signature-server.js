const express = require('express');
const { ethers } = require('ethers');
require('dotenv').config();

const app = express();
app.use(express.json());
app.set('trust proxy', 1);

const port = process.env.PORT || 10000;

// Wallet serveur requis
let gameWallet = null;
if (!process.env.GAME_SERVER_PRIVATE_KEY) {
  console.error('[BOOT] GAME_SERVER_PRIVATE_KEY manquant');
} else {
  gameWallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY);
  console.log('Game Server Signer Address:', gameWallet.address);
}

function requireWallet(req, res, next) {
  if (!gameWallet) return res.status(503).json({ error: 'Server wallet not configured' });
  next();
}

// Auth Firebase (token uniquement)
function requireFirebaseAuth(req, res, next) {
  if (process.env.FIREBASE_REQUIRE_AUTH !== '1') return next();
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  const idToken = auth.slice(7);
  try {
    const admin = require('firebase-admin');
    if (!admin.apps.length) {
      const serviceAccount = {
        type: 'service_account',
        project_id: process.env.FIREBASE_PROJECT_ID,
        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
        private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
        client_email: process.env.FIREBASE_CLIENT_EMAIL,
        client_id: process.env.FIREBASE_CLIENT_ID,
        auth_uri: 'https://accounts.google.com/o/oauth2/auth',
        token_uri: 'https://oauth2.googleapis.com/token',
        auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
      };
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount), projectId: process.env.FIREBASE_PROJECT_ID });
    }
    admin.auth().verifyIdToken(idToken)
      .then(decoded => { req.firebaseAuth = decoded; next(); })
      .catch(() => res.status(401).json({ error: 'Invalid token' }));
  } catch (e) {
    return res.status(500).json({ error: 'Auth service unavailable' });
  }
}

// Health
app.get('/health', (req, res) => {
  res.json({ ok: true, wallet: gameWallet ? gameWallet.address : null, ts: Date.now() });
});

// Match token (anti-replay)
const matchTokens = new Map();
app.post('/api/match/start', requireWallet, requireFirebaseAuth, (req, res) => {
  try {
    const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const ttl = Number(process.env.MATCH_TOKEN_TTL_MS || 2 * 60 * 1000);
    matchTokens.set(token, {
      uid: req.firebaseAuth?.uid || null,
      createdAt: Date.now(),
      expAt: Date.now() + ttl,
      used: false,
      gameId: typeof req.body?.gameId === 'string' ? req.body.gameId.trim() : null
    });
    console.log(`[MATCH-START] Match start requested`);
    console.log(`[MATCH-START] Generated match token: ${token}`);
    return res.json({ success: true, matchToken: token, expiresInMs: ttl });
  } catch (e) { return res.status(500).json({ error: 'Failed to start match' }); }
});

// Photon presence (webhook + helpers)
const fs = require('fs');
const path = require('path');
const DATA_DIR = process.env.DATA_DIR || __dirname;
try { if (DATA_DIR !== __dirname && !fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}

const PHOTON_SESSIONS_FILE = path.join(DATA_DIR, 'photon-sessions.json');
function loadPhotonSessions() { try { if (fs.existsSync(PHOTON_SESSIONS_FILE)) return JSON.parse(fs.readFileSync(PHOTON_SESSIONS_FILE, 'utf8')); } catch {} return {}; }
function savePhotonSessions(s) { try { fs.writeFileSync(PHOTON_SESSIONS_FILE, JSON.stringify(s, null, 2), 'utf8'); } catch {} }
const photonSessions = loadPhotonSessions();

const PHOTON_WEBHOOK_SECRET = process.env.PHOTON_WEBHOOK_SECRET || '';
const PHOTON_PRESENCE_TTL_MS = Number(process.env.PHOTON_PRESENCE_TTL_MS || 60_000);
const PHOTON_GRACE_AFTER_CLOSE_MS = Number(process.env.PHOTON_GRACE_AFTER_CLOSE_MS || 300_000);

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
      if (sinceClose <= PHOTON_GRACE_AFTER_CLOSE_MS && age <= PHOTON_GRACE_AFTER_CLOSE_MS) return true;
    }
    return false;
  } catch { return false; }
}

function findRecentRoomForActor(userId) {
  try {
    if (!userId) return null;
    const now = Date.now();
    let bestRoom = null, bestLast = 0;
    for (const [gid, sess] of Object.entries(photonSessions || {})) {
      const u = sess && sess.users ? sess.users[String(userId)] : null;
      if (!u || typeof u.lastSeen !== 'number') continue;
      const age = now - u.lastSeen;
      const withinPresence = age <= PHOTON_PRESENCE_TTL_MS;
      const withinGrace = sess && sess.closed && typeof sess.closedAt === 'number' ? (now - sess.closedAt) <= PHOTON_GRACE_AFTER_CLOSE_MS : false;
      if (withinPresence || withinGrace) {
        if (u.lastSeen > bestLast) { bestLast = u.lastSeen; bestRoom = gid; }
      }
    }
    return bestRoom;
  } catch { return null; }
}

app.post('/photon/webhook', (req, res) => {
  try {
    if (PHOTON_WEBHOOK_SECRET) {
      const provided = (req.query?.secret || req.headers['x-webhook-secret'] || req.headers['x-photon-secret'] || '').toString().trim();
      if (provided !== PHOTON_WEBHOOK_SECRET) return res.status(401).json({ error: 'Unauthorized' });
    }
    const b = req.body || {};
    const type = String(b.Type || b.type || '').toLowerCase();
    const gameId = String(b.GameId || b.gameId || b.roomName || b.room || '').trim();
    const userId = String(b.UserId || b.userId || '').trim();
    const actorNr = String(b.ActorNr || b.actorNr || b.ActorNumber || b.actorNumber || '').trim();
    if (!gameId) return res.status(400).json({ error: 'Missing GameId' });
    
    const sess = photonSessions[gameId] || { users: {}, createdAt: Date.now(), closed: false };
    console.log(`[PHOTON][WEBHOOK] type=${type} gameId=${gameId} userId=${userId} actor=${actorNr}`);
    
    const touch = (id) => { if (id) sess.users[id] = { lastSeen: Date.now() }; };
    switch (type) {
      case 'create': case 'gamestarted': case 'gamecreated': touch(userId); touch(actorNr); break;
      case 'join': case 'joinrequest': case 'actorjoin': touch(userId); touch(actorNr); break;
      case 'leave': case 'leaverequest': case 'actorleave': touch(userId); touch(actorNr); break;
      case 'close': case 'gameclosed': sess.closed = true; sess.closedAt = Date.now(); break;
      default: touch(userId); touch(actorNr); break;
    }
    photonSessions[gameId] = sess; 
    savePhotonSessions(photonSessions);
    return res.json({ ok: true });
  } catch { return res.status(500).json({ error: 'Webhook error' }); }
});

// 2e update sécurisé (Privy): Auth + matchToken + présence Photon + preflight + txHash
app.post('/api/monad-games-id/submit-score', requireWallet, requireFirebaseAuth, async (req, res) => {
  try {
    if (process.env.ENABLE_PRIVY_SCORE_TO_MONAD !== '1') {
      return res.status(503).json({ error: 'Leaderboard service disabled' });
    }

    const { privyAddress, score, bonus = 0, matchId, matchToken, gameId } = req.body || {};
    if (!/^0x[a-fA-F0-9]{40}$/.test(String(privyAddress || ''))) {
      return res.status(400).json({ error: 'Invalid privyAddress' });
    }
    
    const scoreDelta = Number(score || 0) + Number(bonus || 0);
    if (!Number.isFinite(scoreDelta) || scoreDelta <= 0) {
      return res.status(400).json({ error: 'Score must be > 0' });
    }

    // Match token (anti-replay) avec liaison à l'utilisateur Firebase
    if (process.env.FIREBASE_REQUIRE_AUTH === '1') {
      if (!matchToken || typeof matchToken !== 'string') {
        return res.status(400).json({ error: 'Missing matchToken' });
      }
      const rec = matchTokens.get(matchToken);
      if (!rec) return res.status(401).json({ error: 'Invalid matchToken' });
      if (rec.used) return res.status(401).json({ error: 'Match token already used' });
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

    // Présence Photon (room|actorNr dans matchId, sinon fallback)
    let room = (typeof gameId === 'string' && gameId.trim()) ? gameId.trim() : ((typeof matchId === 'string' && matchId.trim()) ? matchId.trim() : null);
    let userKey = req.firebaseAuth?.uid || null;
    if (typeof matchId === 'string' && matchId.includes('|')) {
      const parts = matchId.split('|'); 
      if (parts[0]) room = parts[0].trim(); 
      if (parts[1]) userKey = parts[1].trim();
    }
    if (!room) { 
      const deduced = findRecentRoomForActor(userKey); 
      if (deduced) room = deduced; 
    }
    if (!room) return res.status(400).json({ error: 'Missing gameId (Photon room)' });
    
    if (!userKey || !hasAcceptablePhotonPresence(room, userKey)) {
      const alt = findRecentRoomForActor(userKey);
      if (!alt || !hasAcceptablePhotonPresence(alt, userKey)) {
        return res.status(403).json({ error: 'Photon presence not verified for this match' });
      }
      room = alt;
    }

    // On-chain (tuple ABI) avec preflight clair, transactions = 0
    const rpcUrl = process.env.MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz/';
    const provider = new ethers.providers.JsonRpcProvider(rpcUrl);
    const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider);
    
    const MONAD_GAMES_ID_CONTRACT = '0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0';
    const abi = ['function updatePlayerData((address player,uint256 score,uint256 transactions) _playerData)'];
    const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, abi, wallet);
    
    const playerData = { 
      player: String(privyAddress).toLowerCase(), 
      score: ethers.BigNumber.from(scoreDelta), 
      transactions: ethers.BigNumber.from(0) 
    };

    // Preflight lisible
    if (process.env.MONAD_PREFLIGHT === '1') {
      try {
        await contract.callStatic.updatePlayerData(playerData);
      } catch (e) {
        return res.status(422).json({ error: 'preflight_failed', details: e.message || String(e) });
      }
    }

    // Gas estimate safe
    let gasLimit = ethers.BigNumber.from(150000);
    try {
      const est = await contract.estimateGas.updatePlayerData(playerData);
      gasLimit = est.mul(120).div(100);
    } catch {}

    // Nonce observable dans les logs
    const nonce = await wallet.getTransactionCount('pending');
    console.log('[NONCE]', nonce);

    const tx = await contract.updatePlayerData(playerData, {
      gasLimit,
      maxPriorityFeePerGas: ethers.utils.parseUnits('2', 'gwei'),
      maxFeePerGas: ethers.utils.parseUnits('100', 'gwei'),
      nonce
    });

    return res.json({
      success: true,
      txHash: tx.hash,
      player: playerData.player,
      scoreAdded: scoreDelta,
      transactions: 0
    });
  } catch (e) {
    return res.status(500).json({ error: 'submit_failed', details: e.message || String(e) });
  }
});

app.listen(port, () => {
  console.log(`Signature server running on port ${port}`);
});
