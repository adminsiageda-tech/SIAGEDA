// Cloud Functions untuk SIAGEDA: ganti password & hapus user oleh admin.
const { onCall, HttpsError } = require('firebase-functions/v2/https');
const admin = require('firebase-admin');
admin.initializeApp();

const ADMIN_EMAIL = 'admin@siageda.app';
const DOMAIN = '@siageda.app';
const BUILTIN = ['admin', 'viewer', 'wadir_pesantren', 'wadir_pengasuhan', 'wadir_pendidikan',
  'wadir_saspras', 'kesekretariatan', 'keuangan', 'lembaga_bahasa', 'mudir_pesantren'];

function assertAdmin(req) {
  if (!req.auth || req.auth.token.email !== ADMIN_EMAIL) throw new HttpsError('permission-denied', 'Hanya admin yang boleh melakukan ini.');
}
function cleanName(v) {
  if (typeof v !== 'string' || !/^[a-z0-9_.-]{3,30}$/.test(v)) throw new HttpsError('invalid-argument', 'Username tidak valid.');
  return v;
}

exports.adminSetPassword = onCall(async (req) => {
  assertAdmin(req);
  const username = cleanName(req.data.username);
  const password = req.data.password;
  if (typeof password !== 'string' || password.length < 6) throw new HttpsError('invalid-argument', 'Password minimal 6 karakter.');
  const user = await admin.auth().getUserByEmail(username + DOMAIN).catch(() => { throw new HttpsError('not-found', 'Akun tidak ditemukan.'); });
  await admin.auth().updateUser(user.uid, { password });
  return { ok: true };
});

exports.adminDeleteUser = onCall(async (req) => {
  assertAdmin(req);
  const username = cleanName(req.data.username);
  if (BUILTIN.includes(username)) throw new HttpsError('failed-precondition', 'Akun bawaan tidak boleh dihapus.');
  try { const user = await admin.auth().getUserByEmail(username + DOMAIN); await admin.auth().deleteUser(user.uid); } catch (e) { /* sudah tidak ada */ }
  await admin.firestore().collection('users').doc(username).delete();
  return { ok: true };
});
