const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { initializeTestEnvironment, assertSucceeds, assertFails } = require('@firebase/rules-unit-testing');

if (!process.env.FIRESTORE_EMULATOR_HOST || !process.env.FIRESTORE_RULES_PATH) {
  test('Reglas: ejecutar con el emulador y FIRESTORE_RULES_PATH', { skip: true }, () => {});
} else {
  let env;
  after(async () => env?.cleanup());

  test('solo propietario modifica perfiles y los dos lados del vínculo pueden leerse', async () => {
    env = await initializeTestEnvironment({
      projectId: 'demo-atrox',
      firestore: { rules: fs.readFileSync(process.env.FIRESTORE_RULES_PATH, 'utf8') }
    });
    await env.withSecurityRulesDisabled(async context => {
      const db = context.firestore();
      await db.doc('users/sponsor').set({ uid: 'sponsor', planTier: 'PERSONAL', maxDevices: 1, linkedAbuelos: ['protected'], linkedProtectors: ['protected'] });
      await db.doc('users/protected').set({ uid: 'protected', planTier: 'FREE', maxDevices: 0, sponsorUid: 'sponsor' });
    });
    const sponsor = env.authenticatedContext('sponsor').firestore();
    const protectedDb = env.authenticatedContext('protected').firestore();
    const stranger = env.authenticatedContext('stranger').firestore();
    await assertSucceeds(sponsor.doc('users/protected').get());
    await assertSucceeds(protectedDb.doc('users/sponsor').get());
    await assertFails(stranger.doc('users/protected').get());
    await assertFails(stranger.doc('users/sponsor').update({ planTier: 'COMMERCE', maxDevices: 20 }));
    await assertFails(sponsor.doc('users/sponsor').update({ linkedAbuelos: [] }));
    await assertFails(sponsor.doc('users/sponsor').update({ planTier: 'FREE', maxDevices: 0 }));
    await assertFails(protectedDb.doc('users/protected').update({ sponsorUid: 'stranger' }));
    await assertSucceeds(sponsor.doc('users/sponsor').update({ fcmToken: 'new-token' }));
    await assertSucceeds(stranger.doc('users/stranger').set({
      uid: 'stranger', planTier: 'FREE', maxDevices: 0, sponsorUid: null, linkedAbuelos: [], linkedProtectors: []
    }));
    await assertSucceeds(stranger.doc('users/stranger').update({ planTier: 'PERSONAL', maxDevices: 1 }));
    await assertSucceeds(stranger.doc('users/stranger').update({ fcmToken: 'own-token' }));
    await assertFails(stranger.doc('pairing_codes/123456').get());
    await assertFails(stranger.doc('pairing_codes/123456').set({ sponsorUid: 'stranger' }));
    await assertFails(stranger.doc('block_events/1').set({ owner_uid: 'protected' }));
    await assertSucceeds(protectedDb.doc('block_events/2').set({ owner_uid: 'protected' }));
    await assertSucceeds(protectedDb.doc('users/protected/daily_stats/2026-09-23').set({ total_blocks: 1 }));
  });
}
