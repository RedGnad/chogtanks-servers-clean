const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
let helmet = null;
require('dotenv').config();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
try { helmet = require('helmet'); app.use(helmet()); } catch (_) { console.warn('[BOOT] helmet non installé - en-têtes sécurité non appliqués'); }
app.use((req, res, next) => { if (req.url.includes('//')) { req.url = req.url.replace(/\/{2,}/g, '/'); } next(); });
app.use(express.json());
try { const rateLimit = require('express-rate-limit'); const windowMs = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000); const max = Number(process.env.RATE_LIMIT_MAX || 300); app.use(rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false })); } catch (_) { console.warn('[BOOT] express-rate-limit non installé - pas de rate limit'); }

function buildRouteLimiter(options) { try { const rateLimit = require('express-rate-limit'); return rateLimit({ standardHeaders: true, legacyHeaders: false, ...options }); } catch (_) { return (req, res, next) => next(); } }
const matchStartLimiter = buildRouteLimiter({ windowMs: Number(process.env.MATCH_START_WINDOW_MS || 60_000), max: Number(process.env.MATCH_START_MAX || 6) });
const submitScoreLimiter = buildRouteLimiter({ windowMs: Number(process.env.SUBMIT_SCORE_WINDOW_MS || 60_000), max: Number(process.env.SUBMIT_SCORE_MAX || 6) });

const defaultAllowed = ['https://redgnad.github.io','https://chogtanks.vercel.app','https://monadclip.vercel.app'];
const allowedFromEnv = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const allowedOrigins = new Set(allowedFromEnv.length ? allowedFromEnv : defaultAllowed);
app.use(cors({ origin: (origin, cb) => { if (!origin) return cb(null, true); if (allowedOrigins.has(origin)) return cb(null, true); return cb(new Error('Not allowed by CORS')); }, credentials: true }));

const port = process.env.PORT || 3001;

let gameWallet = null;
if (!process.env.GAME_SERVER_PRIVATE_KEY) {
  console.error('ERREUR: GAME_SERVER_PRIVATE_KEY non définie. Les endpoints signés seront désactivés tant que la clé n\'est pas configurée.');
} else {
  gameWallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY);
  console.log('Game Server Signer Address:', gameWallet.address);
}

function requireWallet(req, res, next) { if (!gameWallet) { return res.status(503).json({ error: 'Server wallet not configured' }); } next(); }

function requireFirebaseAuth(req, res, next) {
  if (process.env.FIREBASE_REQUIRE_AUTH !== '1') { return next(); }
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) { return res.status(401).json({ error: 'Missing token' }); }
  const idToken = auth.slice(7);
  try {
    const admin = require('firebase-admin');
    if (!admin.apps.length) {
      const serviceAccount = { type: 'service_account', project_id: process.env.FIREBASE_PROJECT_ID, private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID, private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'), client_email: process.env.FIREBASE_CLIENT_EMAIL, client_id: process.env.FIREBASE_CLIENT_ID, auth_uri: 'https://accounts.google.com/o/oauth2/auth', token_uri: 'https://oauth2.googleapis.com/token', auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs', client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}` };
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount), projectId: process.env.FIREBASE_PROJECT_ID });
    }
    admin.auth().verifyIdToken(idToken).then((decoded) => { req.firebaseAuth = decoded; return next(); }).catch((err) => { console.error('[AUTH] verifyIdToken failed:', err.message || err); return res.status(401).json({ error: 'Invalid token' }); });
  } catch (e) { console.error('[AUTH] Firebase admin init error:', e.message || e); return res.status(500).json({ error: 'Auth service unavailable' }); }
}

app.get('/health', (req, res) => { res.status(200).json({ status: 'OK', timestamp: new Date().toISOString(), uptime: process.uptime(), version: '1.0.0', walletReady: Boolean(gameWallet) }); });
app.head('/health', (req, res) => res.sendStatus(200));

app.get('/api/check-username', async (req, res) => {
  try { const wallet = String(req.query.wallet || '').trim(); if (!wallet || !/^0x[a-fA-F0-9]{40}$/.test(wallet)) { return res.status(400).json({ error: 'Invalid wallet parameter' }); } const fetch = require('node-fetch'); const url = `https://monadclip.fun/api/check-wallet?wallet=${wallet}`; const r = await fetch(url, { method: 'GET', headers: { accept: 'application/json' } }); const data = await r.json().catch(() => ({})); return res.status(r.ok ? 200 : 502).json(data); } catch (e) { console.error('[PROXY][check-username] Error:', e.message || e); return res.status(500).json({ error: 'Proxy failed' }); }
});

const matchTokens = new Map();
app.post('/api/match/start', matchStartLimiter, requireWallet, requireFirebaseAuth, async (req, res) => {
  try { console.log('[MATCH-START] Match start requested'); const matchToken = Math.random().toString(36).slice(2) + Date.now().toString(36); const expiresInMs = Number(process.env.MATCH_TOKEN_TTL_MS || 2 * 60 * 1000); const now = Date.now(); const uid = req.firebaseAuth?.uid || null; const providedGameId = typeof req.body?.gameId === 'string' ? req.body.gameId.trim() : null; matchTokens.set(matchToken, { uid, createdAt: now, expAt: now + expiresInMs, used: false, gameId: providedGameId || null }); console.log(`[MATCH-START] Generated match token: ${matchToken}`); return res.json({ matchToken, expiresInMs, success: true }); } catch (error) { console.error('[MATCH-START] Error:', error); res.status(500).json({ error: 'Failed to start match', details: error.message }); }
});

// Photon presence store
const fs = require('fs');
const path = require('path');
const DATA_DIR = process.env.DATA_DIR || __dirname;
try { if (DATA_DIR !== __dirname && !fs.existsSync(DATA_DIR)) { fs.mkdirSync(DATA_DIR, { recursive: true }); } } catch (e) { console.error('[STORAGE] Failed to ensure DATA_DIR:', e.message || e); }
const PHOTON_SESSIONS_FILE = path.join(DATA_DIR, 'photon-sessions.json');
function loadPhotonSessions() { try { if (fs.existsSync(PHOTON_SESSIONS_FILE)) { return JSON.parse(fs.readFileSync(PHOTON_SESSIONS_FILE, 'utf8')); } } catch (e) { console.warn('[PHOTON] load error:', e.message || e); } return {}; }
function savePhotonSessions(state) { try { fs.writeFileSync(PHOTON_SESSIONS_FILE, JSON.stringify(state, null, 2), 'utf8'); } catch (e) { console.warn('[PHOTON] save error:', e.message || e); } }
const photonSessions = loadPhotonSessions();
const PHOTON_WEBHOOK_SECRET = process.env.PHOTON_WEBHOOK_SECRET || '';
const PHOTON_PRESENCE_TTL_MS = Number(process.env.PHOTON_PRESENCE_TTL_MS || 60_000);
const PHOTON_GRACE_AFTER_CLOSE_MS = Number(process.env.PHOTON_GRACE_AFTER_CLOSE_MS || 300_000);
function hasFreshPhotonPresence(gameId, userId) { try { if (!gameId || !userId) return false; const sess = photonSessions[String(gameId)]; if (!sess || !sess.users) return false; const u = sess.users[String(userId)]; if (!u || typeof u.lastSeen !== 'number') return false; return Date.now() - u.lastSeen <= PHOTON_PRESENCE_TTL_MS; } catch (_) { return false; } }
function hasAcceptablePhotonPresence(gameId, userId) { try { if (!gameId || !userId) return false; const now = Date.now(); const sess = photonSessions[String(gameId)]; if (!sess || !sess.users) return false; const u = sess.users[String(userId)]; if (!u || typeof u.lastSeen !== 'number') return false; const age = now - u.lastSeen; if (age <= PHOTON_PRESENCE_TTL_MS) return true; if (sess.closed && typeof sess.closedAt === 'number') { const sinceClose = now - sess.closedAt; if (sinceClose <= PHOTON_GRACE_AFTER_CLOSE_MS && age <= PHOTON_GRACE_AFTER_CLOSE_MS) { return true; } } return false; } catch (_) { return false; } }
function findRecentRoomForActor(userId) { try { if (!userId) return null; const now = Date.now(); let bestRoom = null; let bestLastSeen = 0; for (const [gid, sess] of Object.entries(photonSessions || {})) { const u = sess && sess.users ? sess.users[String(userId)] : null; if (!u || typeof u.lastSeen !== 'number') continue; const age = now - u.lastSeen; const withinPresence = age <= PHOTON_PRESENCE_TTL_MS; const withinGrace = sess && sess.closed && typeof sess.closedAt === 'number' ? now - sess.closedAt <= PHOTON_GRACE_AFTER_CLOSE_MS : false; if (withinPresence || withinGrace) { if (u.lastSeen > bestLastSeen) { bestLastSeen = u.lastSeen; bestRoom = gid; } } } return bestRoom; } catch (_) { return null; } }

app.post('/photon/webhook', (req, res) => {
  try {
    if (PHOTON_WEBHOOK_SECRET) {
      const q = req.query || {}; let providedSecret = q.secret || req.headers['x-webhook-secret'] || req.headers['x-photon-secret']; if (typeof providedSecret === 'string') { providedSecret = providedSecret.trim().replace(/[?#&]+$/g, ''); } if (providedSecret !== PHOTON_WEBHOOK_SECRET) { return res.status(401).json({ error: 'Unauthorized' }); }
    }
    const body = req.body || {}; const type = String(body.Type || body.type || body.eventType || '').toLowerCase(); const gameId = String(body.GameId || body.gameId || body.roomName || body.room || '').trim(); const userId = String(body.UserId || body.userId || '').trim(); const actorKey = String(body.ActorNr || body.actorNr || body.ActorNumber || body.actorNumber || '').trim(); const now = Date.now(); if (!gameId) return res.status(400).json({ error: 'Missing GameId' });
    const sess = photonSessions[gameId] || { users: {}, createdAt: now, closed: false };
    console.log(`[PHOTON][WEBHOOK] type=${type} gameId=${gameId} userId=${userId} actor=${actorKey}`);
    switch (type) {
      case 'create': case 'gamecreated': case 'roomcreated': case 'gamestarted': sess.createdAt = now; if (userId) { sess.users[userId] = { lastSeen: now }; } if (actorKey) { sess.users[actorKey] = { lastSeen: now }; } break;
      case 'join': case 'actorjoin': case 'playerjoined': case 'joinrequest': if (userId) { sess.users[userId] = { lastSeen: now }; } if (actorKey) { sess.users[actorKey] = { lastSeen: now }; } break;
      case 'leave': case 'actorleave': case 'playerleft': case 'leaverequest': if (userId) { sess.users[userId] = { lastSeen: now }; } if (actorKey) { sess.users[actorKey] = { lastSeen: now }; } break;
      case 'close': case 'gameclosed': case 'roomclosed': sess.closed = true; sess.closedAt = now; break;
      case 'event': { const data = body.Data || body.data || {}; const uidFromData = String(data.userId || '').trim(); const effectiveUser = userId || uidFromData; if (effectiveUser) { sess.users[effectiveUser] = { lastSeen: now }; } if (actorKey) { sess.users[actorKey] = { lastSeen: now }; } break; }
      case 'gameproperties': if (userId) { sess.users[userId] = { lastSeen: now }; } if (actorKey) { sess.users[actorKey] = { lastSeen: now }; } break;
      default: if (userId || actorKey) { if (userId) { sess.users[userId] = { lastSeen: now }; } if (actorKey) { sess.users[actorKey] = { lastSeen: now }; } } else { console.log(`[PHOTON][WEBHOOK] Unknown event type: ${type}`); } break;
    }
    photonSessions[gameId] = sess; savePhotonSessions(photonSessions); return res.json({ ok: true });
  } catch (e) { console.error('[PHOTON][WEBHOOK] error:', e.message || e); return res.status(500).json({ error: 'Webhook error' }); }
});

// Leaderboard Monad-only (Privy)
let serverTxMutex = false; const ENABLE_MONAD_BATCH = process.env.ENABLE_MONAD_BATCH === '1';
async function getNextNonce(wallet) { try { const nonce = await wallet.getTransactionCount('pending'); console.log(`[NONCE] Nonce récupéré depuis blockchain: ${nonce}`); return nonce; } catch (error) { console.error('[NONCE] Erreur récupération nonce:', error); throw error; } }

app.post('/api/monad-games-id/submit-score', requireWallet, requireFirebaseAuth, async (req, res) => {
  try {
    if (process.env.ENABLE_PRIVY_SCORE_TO_MONAD !== '1') { return res.status(503).json({ error: 'Leaderboard service disabled' }); }
    const { privyAddress, score, bonus = 0, matchId, matchToken, gameId } = req.body || {};
    if (!privyAddress || !/^0x[a-fA-F0-9]{40}$/.test(String(privyAddress))) { return res.status(400).json({ error: 'Missing or invalid privyAddress' }); }
    const scoreDelta = Number(score || 0) + Number(bonus || 0); if (!Number.isFinite(scoreDelta) || scoreDelta <= 0) { return res.status(400).json({ error: 'Score must be > 0' }); }
    if (process.env.FIREBASE_REQUIRE_AUTH === '1') { if (!matchToken || typeof matchToken !== 'string') { return res.status(400).json({ error: 'Missing matchToken' }); } const rec = matchTokens.get(matchToken); if (!rec) return res.status(401).json({ error: 'Invalid matchToken' }); if (rec.used) return res.status(401).json({ error: 'Match token already used' }); if (rec.expAt < Date.now()) { matchTokens.delete(matchToken); return res.status(401).json({ error: 'Match token expired' }); } const uid = req.firebaseAuth?.uid || null; if (rec.uid && uid && rec.uid !== uid) { return res.status(401).json({ error: 'Match token does not belong to this user' }); } rec.used = true; matchTokens.set(matchToken, rec); }
    let room = (typeof gameId === 'string' && gameId.trim()) ? gameId.trim() : ((typeof matchId === 'string' && matchId.trim()) ? matchId.trim() : null);
    let userKey = req.firebaseAuth?.uid || null; if (typeof matchId === 'string' && matchId.includes('|')) { const parts = matchId.split('|'); if (parts[0]) room = parts[0].trim(); if (parts[1]) userKey = parts[1].trim(); } else if (typeof matchId === 'string') { const m = /^match_(\d+)_/.exec(matchId); if (m && m[1]) userKey = m[1]; }
    if (!room) { const deduced = findRecentRoomForActor(userKey); if (deduced) room = deduced; }
    if (!room) return res.status(400).json({ error: 'Missing gameId (Photon room)' });
    if (!userKey || !hasAcceptablePhotonPresence(room, userKey)) { const altRoom = findRecentRoomForActor(userKey); if (!altRoom || !hasAcceptablePhotonPresence(altRoom, userKey)) { return res.status(403).json({ error: 'Photon presence not verified for this match' }); } room = altRoom; }
    const playerAddr = String(privyAddress).toLowerCase();
    if (process.env.ENABLE_MONAD_BATCH === '1') {
      // batch non implémenté ici (version racine minimale)
    } else {
      (async () => { try { const rpcUrl = process.env.MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz/'; const provider = new ethers.providers.JsonRpcProvider(rpcUrl); const wallet = new ethers.Wallet(process.env.GAME_SERVER_PRIVATE_KEY, provider); const MONAD_GAMES_ID_CONTRACT = '0x4b91a6541Cab9B2256EA7E6787c0aa6BE38b39c0'; const contractABI = ['function updatePlayerData((address player,uint256 score,uint256 transactions) _playerData)']; const contract = new ethers.Contract(MONAD_GAMES_ID_CONTRACT, contractABI, wallet); const playerData = { player: playerAddr, score: ethers.BigNumber.from(scoreDelta), transactions: ethers.BigNumber.from(0) }; const MONAD_PREFLIGHT = process.env.MONAD_PREFLIGHT === '1'; const MONAD_PREFLIGHT_STRICT = process.env.MONAD_PREFLIGHT_STRICT === '1'; if (MONAD_PREFLIGHT) { try { await contract.callStatic.updatePlayerData(playerData); } catch (_) { if (MONAD_PREFLIGHT_STRICT) return; } } let gasLimit = ethers.BigNumber.from(150000); if (MONAD_PREFLIGHT) { try { const est = await contract.estimateGas.updatePlayerData(playerData); gasLimit = est.mul(120).div(100); } catch (_) {} } while (serverTxMutex) { await new Promise(r => setTimeout(r, 50)); } serverTxMutex = true; try { const nonce = await getNextNonce(wallet); await contract.updatePlayerData(playerData, { gasLimit, maxPriorityFeePerGas: ethers.utils.parseUnits('2', 'gwei'), maxFeePerGas: ethers.utils.parseUnits('100', 'gwei'), nonce }); } finally { serverTxMutex = false; } } catch (_) {} })();
    }
    return res.json({ success: true, player: playerAddr, scoreAdded: scoreDelta, tx: 0, validated: true });
  } catch (e) { return res.status(500).json({ error: 'Failed to submit leaderboard score' }); }
});

app.listen(port, () => { console.log(`Signature server running on port ${port}`); console.log(`Game Server Address: ${gameWallet ? gameWallet.address : 'N/A (no private key)'}`); });

process.on('unhandledRejection', (reason) => { console.error('[unhandledRejection]', reason); });
process.on('uncaughtException', (err) => { console.error('[uncaughtException]', err); });


