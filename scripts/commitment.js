// Print the strategy commitment to register in the zkVerify dashboard.
// Usage:
//   npm run commitment            # fresh random salt (first time)
//   STEAL_VFY_SALT=<salt> npm run commitment   # reproduce a commitment
// The printed salt + params are SECRET inputs: set them as Railway env
// vars (STEAL_VFY_PARAMS, STEAL_VFY_SALT) and register the commitment HEX
// in the dashboard. Never commit them to the repo.
'use strict';
const crypto = require('crypto');
const { computeCommitment } = require('../server.js');

(async () => {
  const rawParams = process.env.STEAL_VFY_PARAMS || '10,18,0,0,0,0,0,0';
  const params = rawParams.split(',').map((x) => BigInt(x.trim()));
  if (params.length !== 8) throw new Error('STEAL_VFY_PARAMS must have exactly 8 integers');
  let salt;
  let fresh = false;
  if (process.env.STEAL_VFY_SALT && /^\d+$/.test(process.env.STEAL_VFY_SALT.trim())) {
    salt = BigInt(process.env.STEAL_VFY_SALT.trim());
  } else {
    salt = BigInt('0x' + crypto.randomBytes(16).toString('hex'));
    fresh = true;
  }
  const c = await computeCommitment(params, salt);
  console.log('Strategy Params :', params.map(String).join(','));
  console.log('Salt            :', salt.toString() + (fresh ? '  (freshly generated — save it!)' : ''));
  console.log('Commitment (hex):', c.hex);
  console.log('Commitment (dec):', c.decimal);
  console.log('');
  console.log('Railway variables to set:');
  console.log('  STEAL_VFY_PARAMS=' + params.map(String).join(','));
  console.log('  STEAL_VFY_SALT=' + salt.toString());
  console.log('Dashboard: register the commitment HEX above as your strategy commitment.');
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
