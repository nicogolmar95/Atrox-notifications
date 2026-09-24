const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const documents = new Map();
const sent = [];
const DELETE = Symbol('delete');
const snapshot = (path) => ({
  exists: documents.has(path),
  get: key => documents.get(path)?.[key],
  data: () => documents.get(path)
});
const ref = path => ({ path, get: async () => snapshot(path) });
const firestore = {
  collection: name => ({
    doc: id => ref(`${name}/${id}`),
    limit: () => ({ get: async () => ({ empty: documents.size === 0 }) })
  }),
  runTransaction: async callback => {
    const writes = [];
    const tx = {
      get: async reference => snapshot(reference.path),
      create: (reference, data) => writes.push(() => documents.set(reference.path, data)),
      update: (reference, changes) => writes.push(() => {
        const data = { ...documents.get(reference.path) };
        for (const [key, value] of Object.entries(changes)) {
          if (value === DELETE) delete data[key]; else data[key] = value;
        }
        documents.set(reference.path, data);
      }),
      delete: reference => writes.push(() => documents.delete(reference.path))
    };
    const result = await callback(tx);
    writes.forEach(write => write());
    return result;
  }
};
const admin = {
  apps: [],
  credential: { cert: value => value },
  initializeApp: () => admin.apps.push({}),
  firestore: Object.assign(() => firestore, { FieldValue: { delete: () => DELETE } }),
  auth: () => ({ verifyIdToken: async token => {
    if (!['sponsor', 'protected', 'attacker', 'unlinked'].includes(token)) throw Error('Invalid token');
    return { uid: token };
  } }),
  messaging: () => ({ send: async message => { sent.push(message); return 'message-id'; } })
};
process.env.FIREBASE_SERVICE_ACCOUNT = JSON.stringify({ project_id: 'test' });
const originalLoad = Module._load;
Module._load = function (id, ...args) {
  if (id === 'firebase-admin') return admin;
  return originalLoad.call(this, id, ...args);
};
const { app } = require('../index');
Module._load = originalLoad;
const server = app.listen(0);
after(() => server.close());

async function post(path, uid, data = {}) {
  const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${uid}` },
    body: JSON.stringify(data)
  });
  return { status: response.status, body: await response.json() };
}

function reset() {
  documents.clear(); sent.length = 0;
  documents.set('users/sponsor', { planTier: 'PERSONAL', maxDevices: 1, linkedAbuelos: [], linkedProtectors: [], fcmToken: 'fcm-test' });
  documents.set('users/protected', { planTier: 'FREE', maxDevices: 0 });
  documents.set('users/attacker', { planTier: 'PERSONAL', maxDevices: 1 });
  documents.set('users/unlinked', { planTier: 'FREE', maxDevices: 0 });
}

test('solo sponsor genera, protegido redime una vez, se ocupa un cupo', async () => {
  reset();
  assert.equal((await post('/pairing-codes', 'protected')).status, 403);
  const created = await post('/pairing-codes', 'sponsor');
  assert.equal(created.status, 200);
  assert.match(created.body.code, /^\d{6}$/);
  assert.equal((await post('/pairing-codes/redeem', 'attacker', { code: created.body.code, alias: 'X' })).status, 403);
  assert.equal((await post('/pairing-codes/redeem', 'protected', { code: created.body.code, alias: 'Romina' })).status, 200);
  assert.equal(documents.get('users/protected').sponsorUid, 'sponsor');
  assert.deepEqual(documents.get('users/sponsor').linkedAbuelos, ['protected']);
  assert.equal((await post('/pairing-codes/redeem', 'unlinked', { code: created.body.code, alias: 'Otro' })).status, 404);
  assert.equal((await post('/pairing-codes', 'sponsor')).status, 409);
});

test('desvincular libera cupo aunque haya desaparecido el documento protegido', async () => {
  reset();
  documents.get('users/sponsor').linkedAbuelos = ['protected'];
  documents.get('users/sponsor').linkedProtectors = ['protected'];
  documents.delete('users/protected');
  assert.equal((await post('/links/unlink', 'attacker', { protectedUid: 'protected' })).status, 403);
  assert.equal((await post('/links/unlink', 'sponsor', { protectedUid: 'protected' })).status, 200);
  assert.deepEqual(documents.get('users/sponsor').linkedAbuelos, []);
  assert.equal(documents.has('users/protected'), false);
});

test('push solo al sponsor del emisor vinculado y nunca por tarjeta', async () => {
  reset();
  documents.get('users/sponsor').linkedAbuelos = ['protected'];
  documents.get('users/protected').sponsorUid = 'sponsor';
  documents.get('users/protected').alias = 'Romina';
  assert.equal((await post('/send-alert', 'unlinked', { threatType: 'OTP_THEFT' })).status, 403);
  assert.equal((await post('/send-alert', 'protected', { threatType: 'CREDIT_CARD_EXPOSURE' })).status, 400);
  assert.equal((await post('/send-alert', 'protected', { threatType: 'OTP_THEFT', sponsorUid: 'attacker' })).status, 200);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].token, 'fcm-test');
  assert.match(sent[0].notification.title, /Romina/);
  assert.equal((await post('/send-alert', 'bad-token', { threatType: 'OTP_THEFT' })).status, 401);
});

test('salud del backend y peticiones sin sesión', async () => {
  const response = await fetch(`http://127.0.0.1:${server.address().port}/`);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).status, 'ok');
  assert.equal((await post('/pairing-codes', 'bad-token')).status, 401);
});
