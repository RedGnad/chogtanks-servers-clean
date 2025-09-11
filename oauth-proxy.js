// Bootstrap résilient pour le serveur de signature
// Objectifs:
//  - Conserver un point d'entrée stable (Render -> npm start -> oauth-proxy.js)
//  - Supporter déplacements futurs du fichier signature-server.js
//  - Fournir un heartbeat périodique dans les logs pour montrer que le process vit
//  - Option d'override via variable d'environnement SIGNATURE_SERVER_PATH

const fs = require('fs');
const path = require('path');

const override = process.env.SIGNATURE_SERVER_PATH;
const candidates = override ? [override] : [
	'./signature-server.js',
	'./chogtanks-servers-clean/signature-server.js'
];

function resolveCandidate(candidate) {
	// Supporte chemin absolu ou relatif
	const abs = path.isAbsolute(candidate) ? candidate : path.join(__dirname, candidate);
	return fs.existsSync(abs) ? abs : null;
}

const found = candidates.map(resolveCandidate).find(Boolean);

if (!found) {
	console.error('[BOOT] Aucun signature-server trouvé. Candidats testés:', candidates.join(', '));
	console.error('[BOOT] (Tu peux définir SIGNATURE_SERVER_PATH pour un chemin explicite)');
	process.exit(1);
}

console.log(`[BOOT] Lancement signature server via oauth-proxy -> ${found}`);
try {
	require(found);
} catch (e) {
	console.error('[BOOT] Échec du require du fichier cible:', e.message);
	process.exit(1);
}

// Heartbeat (désactivable en mettant HEARTBEAT_INTERVAL_MS=0)
const HEARTBEAT_INTERVAL_MS = Number(process.env.HEARTBEAT_INTERVAL_MS || 60000);
if (HEARTBEAT_INTERVAL_MS > 0) {
	setInterval(() => {
		// Utilise write plutôt que console.log pour limiter la surcharge format
		process.stdout.write(`[LIVENESS] ${new Date().toISOString()} ok\n`);
	}, HEARTBEAT_INTERVAL_MS).unref();
}

