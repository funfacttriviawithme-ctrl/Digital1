// firebase-config.js - VERSION AMAN DENGAN ENV VARIABLES
const admin = require('firebase-admin');
require('dotenv').config(); // Muat variabel lingkungan dari .env

let serviceAccount;
let firebaseConfig;

try {
  // OPSI 1: Gunakan environment variables (LEBIH AMAN)
  if (process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL) {
    console.log('🔧 Using environment variables for Firebase config');
    
    firebaseConfig = {
      credential: admin.credential.cert({
        type: 'service_account',
        project_id: process.env.FIREBASE_PROJECT_ID || 'digital-52dda',
        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || '',
        private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        client_email: process.env.FIREBASE_CLIENT_EMAIL,
        client_id: process.env.FIREBASE_CLIENT_ID || '',
        auth_uri: 'https://accounts.google.com/o/oauth2/auth',
        token_uri: 'https://oauth2.googleapis.com/token',
        auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
        client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL || '',
        universe_domain: 'googleapis.com'
      })
    };
    
  } 
  // OPSI 2: Fallback ke file JSON (untuk development/local)
  else {
    console.log('📁 Using serviceAccountKey.json file');
    serviceAccount = require('./serviceAccountKey.json'); // Pastikan file ini tidak di-commit ke git!
    
    firebaseConfig = {
      credential: admin.credential.cert(serviceAccount)
    };
  }
  
  // OPSIONAL: Tambahkan database URL dari env
  if (process.env.FIREBASE_DATABASE_URL) {
    firebaseConfig.databaseURL = process.env.FIREBASE_DATABASE_URL;
  }
  
  // Cek jika Firebase sudah diinisialisasi (prevent duplicate apps)
  if (admin.apps.length === 0) {
    admin.initializeApp(firebaseConfig);
    console.log('✅ Firebase Admin SDK initialized successfully');
  } else {
    console.log('ℹ️ Firebase Admin SDK already initialized');
    admin.app(); // Gunakan app yang sudah ada
  }
  
} catch (error) {
  console.error('❌ FIREBASE INITIALIZATION ERROR:', error.message);
  console.error('\n💡 SOLUSI:');
  console.error('1. Pastikan serviceAccountKey.json ada di direktori');
  console.error('2. Atau set environment variables di .env file');
  console.error('3. Periksa format private key (\\n harus diganti dengan newline)');
  process.exit(1);
}

// Buat instance dari Firestore Database dan Firebase Auth
const db = admin.firestore();
const auth = admin.auth();

// Konfigurasi Firestore (opsional)
db.settings({
  ignoreUndefinedProperties: true // Abaikan undefined properties saat save
});

// Ekspor instance untuk digunakan di file lain
module.exports = { 
  db, 
  auth, 
  admin,
  firebaseConfig // untuk debugging
};
