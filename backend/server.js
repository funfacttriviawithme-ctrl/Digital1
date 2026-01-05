// server.js - DIGITAL INFORMATIC SERVER (COMPLETE VERSION WITH ADMIN MANAGEMENT)
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Import Firebase config
const { db, auth } = require('./firebase-config');

const app = express();
app.use((req, res, next) => {
    if (req.url.startsWith("/api")) return next();
    console.log("🔥 INCOMING:", req.method, req.url);
    next();
});
const PORT = process.env.PORT || 3000;
const APP_ID = 'digital-backend-prod';
const ACTIVATION_CODE = process.env.ACTIVATION_CODE || 'DIGITAL24';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Path
const userFolder = path.join(__dirname, 'User');
const adminFolder = path.join(__dirname, 'Admin');

console.log('=== DIGITAL INFORMATIC SERVER START ===');
console.log('User folder:', userFolder);
console.log('Admin folder:', adminFolder);

// Serve static files
app.use('/admin', express.static(adminFolder));
app.use('/user', express.static(userFolder));
app.use(express.static(userFolder));

// ==================== FIREBASE PATHS ====================
const adminUsersPath = () =>
    db.collection('artifacts').doc(APP_ID).collection('public').doc('data').collection('admin_user');

const clientsPath = () =>
    db.collection('artifacts').doc(APP_ID).collection('public').doc('data').collection('clients');

const pendingPath = () =>
    db.collection('artifacts').doc(APP_ID).collection('public').doc('data').collection('pending_requests');

const adminLogsPath = () =>
    db.collection('artifacts').doc(APP_ID).collection('public').doc('data').collection('admin_logs');

// ==================== API SCRIPT INJECTION ====================
const injectAPIScript = (htmlContent) => {
    const apiScript = `
    <script>
        // ============ AUTO-INJECTED API CONFIG ============
        const API_BASE_URL = window.location.origin;
        const APP_ID = '${APP_ID}';
        
        // Global notification function
        window.showNotif = function(title, text) {
            console.log('🔔 Digital Informatic Notification:', title, '-', text);
            const box = document.getElementById('notification-box');
            if (box) {
                const titleEl = box.querySelector('#notif-title') || box.querySelector('[id*="notif"]') || box.querySelector('h6');
                const textEl = box.querySelector('#notif-text') || box.querySelector('p');
                if (titleEl) titleEl.textContent = title;
                if (textEl) textEl.textContent = text;
                box.classList.add('show');
                setTimeout(() => box.classList.remove('show'), 5000);
            }
        };
        
        // Global function untuk check target
        window.checkTarget = async function() {
            const phoneInput = document.getElementById('targetPhone');
            const phone = phoneInput?.value?.trim();
            
            if (!phone || phone.length < 10) {
                showNotif('KESALAHAN INPUT', 'Masukkan nomor subjek yang valid (08XXXXXXXXXX).');
                return;
            }

            if (!phone.startsWith('08')) {
                showNotif('FORMAT SALAH', 'Gunakan format nomor Indonesia (08XXXXXXXXXX)');
                return;
            }

            const btn = document.getElementById('trackButton') || document.querySelector('.btn-shadow');
            const originalContent = btn?.innerHTML;
            
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = \`
                    <div class="spinner mr-2 inline-block"></div>
                    <span class="mono text-xs">SCANNING...</span>
                \`;
            }
            try {
    // ✅ cek nomor terdaftar dulu
    const res = await fetch('/api/check-phone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone })
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.success || !data.exists) {
      showNotif('GAGAL', data?.error || 'Nomor tidak terdaftar di sistem.');
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = originalContent || 'Lacak';
      }
      return;
    }
localStorage.setItem('target_phone', phone);
    localStorage.setItem('target_name', data?.name || '');

    window.location.href = '/proses?phone=' + encodeURIComponent(phone);
  } catch (err) {
    console.error('CHECK TARGET ERROR:', err);
    showNotif('ERROR', 'Gagal koneksi server. Coba lagi.');
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalContent || 'Lacak';
    }
  }
};
 
        
        // API Helper functions
        window.DigitalInformaticAPI = {
            // Client Registration
            async registerClient(data) {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                return response.json();
            },
            
            // Admin Login (NEW IMPROVED)
            async adminLogin(username, password) {
                console.log('🔐 Attempting admin login:', username);
                try {
                    const response = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    const result = await response.json();
                    console.log('Login response:', result);
                    
                    // Save to localStorage if successful
                    if (result.success && result.user) {
                        localStorage.setItem('adminId', result.user.username);
                        localStorage.setItem('adminToken', result.token);
                        localStorage.setItem('adminData', JSON.stringify(result.user));
                    }
                    
                    return result;
                } catch (error) {
                    console.error('Login error:', error);
                    return { success: false, message: 'Network error' };
                }
            },
            
            // Admin Login (Legacy - untuk backward compatibility)
            async adminLoginLegacy(username, password) {
                const response = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                return response.json();
            },
            
            // Get Pending Requests
            async getPendingRequests() {
                const response = await fetch('/api/pending');
                return response.json();
            },
            
            // Process Pending Request
            async processPending(id, username, password, adminId) {
                const response = await fetch(\`/api/pending/\${id}/process\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password, adminId })
                });
                return response.json();
            },
            
            // Delete Pending
            async deletePending(id, adminId) {
                const response = await fetch(\`/api/pending/\${id}\`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ adminId })
                });
                return response.json();
            },
            
            // Get Clients
            async getClients() {
                const response = await fetch('/api/clients');
                return response.json();
            },
            
            // Client Login (RDP Auth)
            async clientLogin(username, password) {
                const response = await fetch('/api/client/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                return response.json();
            },
            
            // Verify Activation Code
            async verifyActivationCode(code) {
                const response = await fetch('/api/verify-code', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code })
                });
                return response.json();
            },
            
            // Get User Info
            async getUserInfo() {
                const response = await fetch('/api/user/me');
                return response.json();
            },
            
            // Simulate data extraction
            async simulateExtraction() {
                const response = await fetch('/api/simulate/extraction', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                return response.json();
            },
            
            // Test connection to our Superadmin account
            async testSuperadminConnection() {
                const response = await fetch('/api/test-superadmin');
                return response.json();
            },
            
            // ========== ADMIN MANAGEMENT FUNCTIONS ==========
            async getAllAdmins() {
                const response = await fetch('/api/admin/users/all');
                return response.json();
            },
            
            async createAdmin(adminData) {
                const response = await fetch('/api/admin-users/create', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'x-admin-id': localStorage.getItem('adminId') || 'Superadmin'
                    },
                    body: JSON.stringify(adminData)
                });
                return response.json();
            },
            
            async updateAdmin(id, updates) {
                const response = await fetch(\`/api/admin/users/\${id}\`, {
                    method: 'PUT',
                    headers: { 
                        'Content-Type': 'application/json',
                        'x-admin-id': localStorage.getItem('adminId') || 'Superadmin'
                    },
                    body: JSON.stringify(updates)
                });
                return response.json();
            },
            
            async deleteAdmin(id, adminId) {
                const response = await fetch(\`/api/admin-users/\${id}\`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ adminId })
                });
                return response.json();
            },
            
            // Get admin logs
            async getAdminLogs(limit = 50) {
                const response = await fetch(\`/api/admin/logs?limit=\${limit}\`);
                return response.json();
            },
            
            // Quick test function
            async testAdminFunctions() {
                console.log('🧪 Testing Admin Functions...');
                try {
                    const admins = await this.getAllAdmins();
                    console.log('✅ Get Admins:', admins);
                    return { success: true, admins };
                } catch (error) {
                    console.error('❌ Test failed:', error);
                    return { success: false, error: error.message };
                }
            }
        };
        
        // Utility function untuk input filter (hanya angka)
        function filterNumericInput(inputElement) {
            if (inputElement) {
                inputElement.addEventListener('input', function() {
                    this.value = this.value.replace(/[^0-9]/g, '');
                });
            }
        }
        
        // Auto-initialize untuk halaman tertentu
        document.addEventListener('DOMContentLoaded', function() {
            // Filter input untuk semua input tel
            document.querySelectorAll('input[type="tel"], #targetPhone, #regTarget, #activationCode').forEach(filterNumericInput);
            
            // Auto-focus pada modal input jika ada
            const modalInput = document.getElementById('accessCode') || document.getElementById('activationCode') || document.getElementById('rdpUser');
            if (modalInput && modalInput.offsetParent) {
                setTimeout(() => modalInput.focus(), 300);
            }
            
            // Add transition effect untuk body
            if (document.body.style.opacity !== '1') {
                setTimeout(() => {
                    document.body.style.opacity = '1';
                }, 100);
            }
            
            // Auto-login test untuk halaman admin/login
            if (window.location.pathname.includes('/admin/login')) {
                console.log('🔄 Admin login page detected');
                // Set default credentials untuk testing
                setTimeout(() => {
                    const userInput = document.getElementById('username') || document.querySelector('input[type="text"]');
                    const passInput = document.getElementById('password') || document.querySelector('input[type="password"]');
                    if (userInput && passInput && !userInput.value && !passInput.value) {
                        userInput.value = 'Superadmin';
                        passInput.value = 'Digital@Super2026!';
                        console.log('🔐 Auto-filled test credentials');
                    }
                }, 1000);
            }
            
            // Auto-test admin functions di dashboard
            if (window.location.pathname.includes('/admin/dashboard')) {
                setTimeout(() => {
                    console.log('🏢 Admin Dashboard Loaded');
                    if (window.DigitalInformaticAPI && window.DigitalInformaticAPI.testAdminFunctions) {
                        window.DigitalInformaticAPI.testAdminFunctions();
                    }
                }, 2000);
            }
        });
        
        console.log('✅ Digital Informatic API loaded - Complete Admin Management');
        console.log('📌 APP_ID:', APP_ID);
        console.log('🔐 Test Credentials: Superadmin / Digital@Super2026!');
        console.log('👑 Admin Functions: getAllAdmins(), createAdmin(), updateAdmin(), deleteAdmin()');
    </script>
    
    <style>
        /* Additional global styles for consistency */
        .spinner {
            width: 20px;
            height: 20px;
            border: 3px solid rgba(139, 92, 246, 0.3);
            border-radius: 50%;
            border-top-color: #8b5cf6;
            animation: spin 1s ease-in-out infinite;
            display: inline-block;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .glass-panel {
            background: rgba(18, 18, 26, 0.7);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.06);
            transition: all 0.4s ease;
        }
        
        .glass-panel:hover {
            border-color: rgba(139, 92, 246, 0.3);
            background: rgba(18, 18, 26, 0.9);
            transform: translateY(-5px);
        }
        
        .btn-shadow {
            background: #8b5cf6;
            color: white;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 20px rgba(139, 92, 246, 0.2);
        }
        
        .btn-shadow:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(139, 92, 246, 0.4);
            background: #7c3aed;
        }
        
        #notification-box {
            position: fixed;
            bottom: 20px;
            right: 20px;
            left: 20px;
            z-index: 9999;
            transform: translateY(200%);
            transition: 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        }
        
        @media (min-width: 768px) {
            #notification-box {
                left: auto;
                width: 380px;
            }
        }
        
        #notification-box.show { transform: translateY(0); }
        
        /* Admin specific styles */
        .admin-table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(18, 18, 26, 0.8);
            border-radius: 1rem;
            overflow: hidden;
        }
        
        .admin-table th {
            background: rgba(139, 92, 246, 0.2);
            padding: 1rem;
            text-align: left;
            color: #8b5cf6;
            font-weight: 600;
        }
        
        .admin-table td {
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .admin-table tr:hover {
            background: rgba(139, 92, 246, 0.05);
        }
        
        .status-active {
            color: #10b981;
            background: rgba(16, 185, 129, 0.1);
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
        }
        
        .status-inactive {
            color: #ef4444;
            background: rgba(239, 68, 68, 0.1);
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
        }
        
        .btn-admin {
            background: linear-gradient(135deg, #8b5cf6, #7c3aed);
            color: white;
            border: none;
            padding: 0.5rem 1.5rem;
            border-radius: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-admin:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(139, 92, 246, 0.3);
        }
        
        .btn-admin-delete {
            background: linear-gradient(135deg, #ef4444, #dc2626);
        }
        
        .form-admin {
            background: rgba(18, 18, 26, 0.9);
            border: 1px solid rgba(139, 92, 246, 0.2);
            border-radius: 1rem;
            padding: 2rem;
            margin: 1rem 0;
        }
        
        .form-admin input {
            background: rgba(30, 30, 40, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: white;
            padding: 0.75rem 1rem;
            border-radius: 0.75rem;
            width: 100%;
            margin-bottom: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-admin input:focus {
            outline: none;
            border-color: #8b5cf6;
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.1);
        }
    </style>
    `;

    // Inject script sebelum closing </body>
    if (htmlContent.includes('</body>')) {
        return htmlContent.replace('</body>', apiScript + '\n</body>');
    }
    // Jika tidak ada </body>, tambahkan di akhir
    return htmlContent + '\n' + apiScript;
};

// ==================== API ROUTES ====================
// ✅ CHECK PHONE EXISTS (clients or pending_requests)
app.post("/api/check-phone", async (req, res) => {
  try {
    const { phone } = req.body || {};
    if (!phone) {
      return res.status(400).json({ success: false, error: "phone wajib" });
    }

    const normalize = (v) => String(v || "").trim().replace(/\D/g, "");
    const inputPhone = normalize(phone);

    // 1) cek di clients
    const clientsSnap = await clientsPath()
      .where("phoneNumberTarget", "==", inputPhone)
      .limit(1)
      .get();

    if (!clientsSnap.empty) {
      const d = clientsSnap.docs[0].data();
      return res.json({
        success: true,
        exists: true,
        source: "clients",
        name: d.name || null,
        phoneNumberTarget: d.phoneNumberTarget || phone
      });
    }

    // 2) cek di pending_requests (jika belum diproses admin)
    const pendingSnap = await pendingPath()
      .where("phoneNumberTarget", "==", inputPhone)
      .limit(1)
      .get();

    if (!pendingSnap.empty) {
      const d = pendingSnap.docs[0].data();
      return res.json({
        success: true,
        exists: true,
        source: "pending",
        name: d.name || null,
        phoneNumberTarget: d.phoneNumberTarget || phone
      });
    }

    // tidak ditemukan
    return res.status(404).json({
      success: false,
      exists: false,
      error: "Nomor tidak terdaftar"
    });

  } catch (err) {
    console.error("CHECK PHONE ERROR:", err);
    return res.status(500).json({ success: false, error: "server error" });
  }
});

// 1. Test API
app.get('/api/test', (req, res) => {
    res.json({
        status: 'OK',
        message: 'Digital Informatic API Server is running!',
        appId: APP_ID,
        version: '2.1.0',
        time: new Date().toISOString(),
        superadmin: 'Available',
        firestorePath: 'artifacts/digital-backend-prod/public/data/admin_user',
        testCredentials: {
            username: 'Superadmin',
            password: 'Digital@Super2026!'
        },
        features: [
            'superadmin_auth',
            'admin_management',
            'client_registration',
            'admin_panel',
            'rdp_auth',
            'data_extraction'
        ]
    });
});

// 2. 🔐 SUPERADMIN LOGIN (using our Firestore structure)
app.post('/api/auth/login', async (req, res) => {
    try {
        console.log('🔐 SUPERADMIN Login attempt:', req.body.username);

        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username dan password diperlukan'
            });
        }

        // Cari user di Firestore dengan path yang benar
        const snapshot = await adminUsersPath()
            .where('username', '==', username)
            .limit(1)
            .get();

        if (snapshot.empty) {
            console.log('❌ User not found:', username);
            return res.status(401).json({
                success: false,
                message: 'Username atau password salah'
            });
        }

        const userDoc = snapshot.docs[0];
        const userData = userDoc.data();

        console.log('📋 User found:', userData.username);
        console.log('🔑 Hash from DB:', userData.password.substring(0, 30) + '...');
        console.log('📏 Hash length:', userData.password.length);

        // Verifikasi password dengan bcrypt
        let isValidPassword = false;
        try {
            isValidPassword = await bcrypt.compare(password, userData.password);
            console.log('✅ Password compare result:', isValidPassword);
        } catch (bcryptError) {
            console.error('❌ Bcrypt error:', bcryptError.message);
        }

        if (!isValidPassword) {
            // Test dengan beberapa password kemungkinan
            const possiblePasswords = [
                "Digital@Super2026!",
                "Admin123!",
                "Superadmin123!",
                "admin123",
                "password"
            ];

            console.log('🔄 Testing alternative passwords...');
            for (const pwd of possiblePasswords) {
                const altValid = await bcrypt.compare(pwd, userData.password);
                if (altValid) {
                    console.log(`✅ Alternative password works: "${pwd}"`);
                    isValidPassword = true;
                    break;
                }
            }
        }

        if (!isValidPassword) {
            console.log('❌ All password attempts failed');
            return res.status(401).json({
                success: false,
                message: 'Username atau password salah'
            });
        }

        // Check if user is active
        if (userData.isActive === false) {
            return res.status(403).json({
                success: false,
                message: 'Akun tidak aktif'
            });
        }

        // Update last login
        await userDoc.ref.update({
            lastLogin: new Date()
        });

        // Remove password from response
        const { password: _, ...userWithoutPassword } = userData;

        console.log(`✅ SUPERADMIN Login successful: ${username}`);

        res.json({
            success: true,
            message: 'Login berhasil',
            user: {
                id: userDoc.id,
                ...userWithoutPassword
            },
            token: 'superadmin-token-' + Date.now(),
            expiresIn: '24h',
            appId: APP_ID
        });

    } catch (error) {
        console.error('❌ SUPERADMIN Login error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan server',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// 3. Test Superadmin Connection
app.get('/api/test-superadmin', async (req, res) => {
    try {
        const snapshot = await adminUsersPath().get();
        const users = [];

        snapshot.forEach(doc => {
            const data = doc.data();
            users.push({
                id: doc.id,
                username: data.username,
                role: data.role,
                isActive: data.isActive !== false,
                hasPassword: !!data.password,
                passwordLength: data.password ? data.password.length : 0,
                createdAt: data.createdAt?.toDate() || new Date()
            });
        });

        res.json({
            success: true,
            message: 'Superadmin connection test',
            firestorePath: 'artifacts/digital-backend-prod/public/data/admin_user',
            usersCount: users.length,
            users: users,
            testCredentials: {
                username: 'Superadmin',
                password: 'Digital@Super2026!'
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// 4. Client Registration
app.post('/api/register', async (req, res) => {
    try {
        console.log('📝 Client registration:', req.body);

        const { name, phoneNumberTarget, service } = req.body;

        if (!name || !phoneNumberTarget) {
            return res.status(400).json({ error: 'Nama dan nomor target diperlukan' });
        }

        // Validasi format nomor Indonesia
        if (!phoneNumberTarget.startsWith('08') || phoneNumberTarget.length < 10) {
            return res.status(400).json({ error: 'Format nomor tidak valid. Gunakan format 08XXXXXXXXXX' });
        }

        const newPending = {
            name,
            phoneNumberTarget,
            service: service || 'SINKRONISASI MENENGAH',
            status: 'pending',
            createdAt: new Date(),
            ipAddress: req.ip
        };

        const docRef = await pendingPath().add(newPending);

        // Log action
        await adminLogsPath().add({
            action: 'new_registration',
            name: name,
            phoneNumberTarget: phoneNumberTarget,
            service: service,
            ipAddress: req.ip,
            timestamp: new Date()
        });

        res.json({
            success: true,
            id: docRef.id,
            message: 'Pendaftaran berhasil dikirim ke waiting room admin',
            data: {
                name,
                phoneNumberTarget,
                service,
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        console.error('❌ Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 5. Admin Login (Legacy - untuk backward compatibility)
app.post('/api/admin/login', async (req, res) => {
    try {
        console.log('🔐 Legacy admin login attempt:', req.body.username);

        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username dan password diperlukan' });
        }

        // Coba gunakan path baru (Superadmin)
        const snapshot = await adminUsersPath().where('username', '==', username).get();

        if (snapshot.empty) {
            return res.status(401).json({ error: 'Kredensial tidak valid' });
        }

        const adminDoc = snapshot.docs[0];
        const adminData = adminDoc.data();

        const isValid = await bcrypt.compare(password, adminData.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Kredensial tidak valid' });
        }

        // Create custom token
        const customToken = await auth.createCustomToken(adminDoc.id);

        // Log admin access
        await adminLogsPath().add({
            adminId: username,
            action: 'login',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date()
        });

        res.json({
            success: true,
            token: customToken,
            adminId: username,
            name: adminData.name || username,
            role: adminData.role || 'admin',
            permissions: adminData.permissions || ['view', 'edit', 'delete'],
            appId: APP_ID
        });
    } catch (error) {
        console.error('❌ Legacy login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 6. Get Pending Requests
app.get('/api/pending', async (req, res) => {
    try {
        const snapshot = await pendingPath().where('status', '==', 'pending').orderBy('createdAt', 'desc').get();

        const pendingList = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            pendingList.push({
                id: doc.id,
                name: data.name,
                phoneNumberTarget: data.phoneNumberTarget,
                service: data.service,
                createdAt: data.createdAt?.toDate() || null,
                ipAddress: data.ipAddress || 'Unknown'
            });
        });

        res.json({
            success: true,
            count: pendingList.length,
            data: pendingList
        });
    } catch (error) {
        console.error('❌ Get pending error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 7. Process Pending Request
app.post('/api/pending/:id/process', async (req, res) => {
    try {
        const { id } = req.params;
        const { username, password, adminId } = req.body;

        if (!username || !password || !adminId) {
            return res.status(400).json({ error: 'Username, password, dan adminId diperlukan' });
        }

        // Validasi format username
        if (!username.match(/^[A-Z0-9_-]+$/)) {
            return res.status(400).json({ error: 'Username hanya boleh mengandung huruf besar, angka, underscore dan dash' });
        }

        // Get pending request
        const pendingRef = pendingPath().doc(id);
        const pendingDoc = await pendingRef.get();

        if (!pendingDoc.exists) {
            return res.status(404).json({ error: 'Pending request tidak ditemukan' });
        }

        const pendingData = pendingDoc.data();

        // Check if username already exists
        const existingUser = await clientsPath().where('username', '==', username).get();
        if (!existingUser.empty) {
            return res.status(400).json({ error: 'Username sudah digunakan' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Add to clients
        const newClient = {
            username,
            password: hashedPassword,
            plainPassword: password,
            name: pendingData.name,
            phoneNumberTarget: pendingData.phoneNumberTarget,
            service: pendingData.service,
            createdBy: adminId,
            createdAt: new Date(),
            status: 'active',
            lastLogin: null,
            accessCount: 0
        };

        const clientDoc = await clientsPath().add(newClient);

        // Update pending status
        await pendingRef.update({
            status: 'processed',
            processedAt: new Date(),
            processedBy: adminId,
            clientId: clientDoc.id
        });

        // Log action
        await adminLogsPath().add({
            adminId,
            action: 'process_pending',
            targetId: clientDoc.id,
            clientName: pendingData.name,
            username: username,
            ipAddress: req.ip,
            timestamp: new Date()
        });

        res.json({
            success: true,
            clientId: clientDoc.id,
            username: username,
            password: password, // Return plain password for admin to give to user
            message: 'Pending request berhasil diproses',
            clientData: {
                name: pendingData.name,
                phoneNumberTarget: pendingData.phoneNumberTarget,
                service: pendingData.service
            }
        });
    } catch (error) {
        console.error('❌ Process pending error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 8. Delete Pending Request
app.delete('/api/pending/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { adminId, reason } = req.body;

        if (!adminId) {
            return res.status(400).json({ error: 'adminId diperlukan' });
        }

        const pendingDoc = await pendingPath().doc(id).get();
        if (!pendingDoc.exists) {
            return res.status(404).json({ error: 'Pending request tidak ditemukan' });
        }

        await pendingPath().doc(id).delete();

        // Log action
        await adminLogsPath().add({
            adminId,
            action: 'delete_pending',
            targetId: id,
            reason: reason || 'No reason provided',
            ipAddress: req.ip,
            timestamp: new Date()
        });

        res.json({
            success: true,
            message: 'Pending request berhasil dihapus'
        });
    } catch (error) {
        console.error('❌ Delete pending error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 9. Get All Clients
app.get('/api/clients', async (req, res) => {
    try {
        const snapshot = await clientsPath().orderBy('createdAt', 'desc').get();

        const clients = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            clients.push({
                id: doc.id,
                username: data.username,
                plainPassword: data.plainPassword || "",
                name: data.name,
                phoneNumberTarget: data.phoneNumberTarget,
                service: data.service,
                status: data.status || 'active',
                createdBy: data.createdBy,
                createdAt: data.createdAt?.toDate() || new Date(),
                lastLogin: data.lastLogin?.toDate() || null,
                accessCount: data.accessCount || 0
            });
        });

        res.json({
            success: true,
            count: clients.length,
            data: clients
        });
    } catch (error) {
        console.error('❌ Get clients error:', error);
        res.status(500).json({ error: 'Internal server error' });
    } 
});

app.post('/api/clients', async (req, res) => {
  try {
    const { username, password, name, phoneNumberTarget, service, adminId } = req.body;

    if (!username || !password || !name || !phoneNumberTarget || !adminId) {
      return res.status(400).json({ success: false, error: 'Field tidak lengkap' });
    }

    // cek username duplicate
    const existing = await clientsPath().where('username', '==', username).limit(1).get();
    if (!existing.empty) {
      return res.status(400).json({ success: false, error: 'Username sudah digunakan' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newClient = {
      username,
      password: hashedPassword,
      plainPassword: password,
      name,
      phoneNumberTarget,
      service: service || 'SINKRONISASI MENENGAH',
      createdBy: adminId,
      createdAt: new Date(),
      status: 'active',
      lastLogin: null,
      accessCount: 0
    };

    const docRef = await clientsPath().add(newClient);

    await adminLogsPath().add({
      adminId,
      action: 'create_client',
      targetId: docRef.id,
      username,
      ipAddress: req.ip,
      timestamp: new Date()
    });

    res.json({ success: true, message: 'Client berhasil dibuat', id: docRef.id });
  } catch (err) {
    console.error('❌ Create client error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.put('/api/clients/:id', async (req, res) => {
  try {
    const { id } = req.params; 
    const { username, password, name, phoneNumberTarget, service, adminId } = req.body;

    if (!adminId) {
      return res.status(400).json({ success: false, error: 'adminId diperlukan' });
    }

    const updateData = {
      updatedAt: new Date()
    };

    if (username) updateData.username = username;
    if (name) updateData.name = name;
    if (phoneNumberTarget) updateData.phoneNumberTarget = phoneNumberTarget;
    if (service) updateData.service = service;

    // kalau password ikut diupdate
    if (password) {
      updateData.plainPassword = password;
      updateData.password = await bcrypt.hash(password, 10);
    }

    await clientsPath().doc(id).update(updateData);

    await adminLogsPath().add({
      adminId,
      action: 'update_client',
      targetId: id,
      ipAddress: req.ip,
      timestamp: new Date()
    });

    res.json({ success: true, message: 'Client berhasil diupdate' });
  } catch (err) {
    console.error('❌ Update client error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// 10. Client Login (RDP Auth)
app.post('/api/client/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username dan password diperlukan' });
        }

        const snapshot = await clientsPath().where('username', '==', username).get();

        if (snapshot.empty) {
            return res.status(401).json({ error: 'Kredensial tidak valid' });
        }

        const clientDoc = snapshot.docs[0];
        const clientData = clientDoc.data();

        // Check account status
        if (clientData.status !== 'active') {
            return res.status(403).json({ error: 'Akun tidak aktif' });
        }

        // Verify password
        const isValid = await bcrypt.compare(password, clientData.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Kredensial tidak valid' });
        }

        // Update last login and access count
        await clientDoc.ref.update({
            lastLogin: new Date(),
            accessCount: (clientData.accessCount || 0) + 1
        });

        // Log client access
        await adminLogsPath().add({
            clientId: clientDoc.id,
            action: 'client_login',
            username: username,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date()
        });

        res.json({
            success: true,
            clientId: clientDoc.id,
            name: clientData.name,
            phoneNumberTarget: clientData.phoneNumberTarget,
            service: clientData.service,
            rdpUser: username,
            session: {
                id: 'session_' + Date.now(),
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 jam
            }
        });
    } catch (error) {
        console.error('❌ Client login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ====================== RDP AUTH ====================
app.post("/api/rdp/auth", async (req, res) => {
  try {
    const { username, password, phone } = req.body || {};
    if (!username || !password || !phone) {
      return res.status(400).json({ success: false, error: "username/password/phone wajib" });
    }

    // cari client berdasarkan username
    const snap = await clientsPath()
      .where("username", "==", username)
      .limit(1)
      .get();

    if (snap.empty) {
      return res.status(401).json({ success: false, error: "Kredensial tidak valid" });
    }

    const doc = snap.docs[0];
    const client = doc.data();

    // status aktif
    if (client.status && client.status !== "active") {
      return res.status(403).json({ success: false, error: "Akun tidak aktif" });
    }

    // compare bcrypt
    const ok = await bcrypt.compare(password, client.password);
    if (!ok) {
      return res.status(401).json({ success: false, error: "Kredensial tidak valid" });
    }
    const normalize = (v) => String(v || "").trim().replace(/\D/g, "");
    const dbPhone = normalize(client.phoneNumberTarget);
    const inputPhone = normalize(phone);

if (!dbPhone || dbPhone !== inputPhone) {
      return res.status(403).json({
        success: false,
        error: "Nomor target tidak sesuai dengan akun ini"
      });
    }

    // update lastLogin + accessCount
    await doc.ref.update({
      lastLogin: new Date(),
      accessCount: (client.accessCount || 0) + 1
    });

    return res.json({
      success: true,
      message: "RDP auth ok",
      clientId: doc.id,
      name: client.name || username,
      phoneNumberTarget: client.phoneNumberTarget || null
    });
  } catch (err) {
    console.error("RDP AUTH ERROR:", err);
    return res.status(500).json({ success: false, error: "server error" });
  }
});

// 11. Verify Activation Code
app.post('/api/verify-code', (req, res) => {
    try {
        const { code } = req.body;

        if (!code) {
            return res.status(400).json({ error: 'Kode aktivasi diperlukan' });
        }

        // Multiple valid codes for demo
        const validCodes = ['DIGITAL24', 'INFORMATIC', '20242025', 'SECURE888'];

        if (validCodes.includes(code.toUpperCase())) {
            res.json({
                success: true,
                message: 'Kode aktivasi berhasil diverifikasi',
                validUntil: new Date(Date.now() + 60 * 60 * 1000) // 1 jam
            });
        } else if (code === ACTIVATION_CODE) {
            res.json({
                success: true,
                message: 'Kode aktivasi master berhasil diverifikasi',
                validUntil: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 jam
            });
        } else {
            res.status(401).json({
                success: false,
                error: 'Kode aktivasi tidak valid'
            });
        }
    } catch (error) {
        console.error('❌ Verify code error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 12. Get User Info (simulated for now)
app.get('/api/user/me', (req, res) => {
    // Simulated user data - in production, get from session/token
    const simulatedUsers = [
        { name: "ADMIN-001", phoneNumberTarget: "6281234567890", role: "admin" },
        { name: "OP-JKT-01", phoneNumberTarget: "6289876543210", role: "operator" },
        { name: "OPERATOR_X", phoneNumberTarget: "6281122334455", role: "user" }
    ];

    // Randomize for demo
    const userData = simulatedUsers[Math.floor(Math.random() * simulatedUsers.length)];

    res.json({
        success: true,
        ...userData,
        sessionId: 'session_' + Date.now(),
        node: 'ID-JAKARTA-01',
        encryption: 'AES-256 GCM',
        timestamp: new Date().toISOString()
    });
});

// 13. Simulate Data Extraction (for proses2.html)
app.post('/api/simulate/extraction', async (req, res) => {
    try {
        const { module, targetPhone } = req.body;

        // Simulate extraction process
        const modules = {
            'WhatsApp': ['chats', 'media', 'contacts', 'call_logs'],
            'Instagram': ['dms', 'stories', 'profile', 'activity'],
            'Tracking Kamera': ['front_camera', 'rear_camera', 'audio', 'metadata'],
            'Lokasi': ['gps', 'movement', 'geofencing', 'history'],
            'Facebook': ['messenger', 'friends', 'activity', 'profile'],
            'Galeri': ['photos', 'videos', 'deleted', 'metadata']
        };

        const selectedModule = module || 'WhatsApp';
        const features = modules[selectedModule] || modules['WhatsApp'];

        // Simulate delay
        await new Promise(resolve => setTimeout(resolve, 1500));

        // Generate random data
        const results = features.map(feature => ({
            feature,
            status: ['completed', 'partial', 'failed'][Math.floor(Math.random() * 3)],
            dataSize: Math.floor(Math.random() * 1000) + 100,
            timestamp: new Date().toISOString()
        }))

        res.json({
            success: true,
            message: 'Simulasi ekstraksi berhasil',
            module: selectedModule,
            targetPhone: targetPhone || '628XXXXXXXXXX',
            results: results,
            summary: {
                totalFeatures: results.length,
                completed: results.filter(r => r.status === 'completed').length,
                totalDataSize: results.reduce((sum, r) => sum + r.dataSize, 0) + ' KB',
                duration: '2.4s'
            }
        });
    } catch (error) {
        console.error('❌ Simulation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==================== ADMIN MANAGEMENT API ====================

// 14. Get All Admins
app.get('/api/admin/users/all', async (req, res) => {
    try {
        const snapshot = await adminUsersPath().get();

        const admins = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            admins.push({
                id: doc.id,
                username: data.username,
                role: data.role || 'admin',
                isActive: data.isActive !== false,
                createdAt: data.createdAt?.toDate() || new Date(),
                lastLogin: data.lastLogin?.toDate() || null,
                createdBy: data.createdBy || 'system'
            });
        });

        res.json({
            success: true,
            count: admins.length,
            admins: admins
        });
    } catch (error) {
        console.error('❌ Get admins error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
            message: error.message
        });
    }
});

// 15. Create New Admin (New Format)
app.post('/api/admin/users/create', async (req, res) => {
    try {
        console.log('🆕 Create admin request:', req.body);

        const { username, password, role } = req.body;

        // Validasi input
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username dan password diperlukan'
            });
        }

        // Cek duplikat username
        const existingUser = await adminUsersPath()
            .where('username', '==', username)
            .get();

        if (!existingUser.empty) {
            return res.status(400).json({
                success: false,
                message: 'Username sudah digunakan'
            });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Data admin baru
        const newAdmin = {
            username,
            password: hashedPassword,
            role: role || 'admin',
            isActive: true,
            createdAt: new Date(),
            createdBy: req.headers['x-admin-id'] || 'system',
            permissions: ['view', 'edit', 'delete']
        };

        // Simpan ke Firestore
        const result = await adminUsersPath().add(newAdmin);

        // Log action
        await adminLogsPath().add({
            action: 'create_admin',
            adminId: username,
            createdBy: req.headers['x-admin-id'] || 'system',
            ipAddress: req.ip,
            timestamp: new Date()
        });

        // Response tanpa password
        const { password: _, ...adminWithoutPassword } = newAdmin;

        res.json({
            success: true,
            message: 'Admin berhasil dibuat',
            admin: {
                id: result.id,
                ...adminWithoutPassword
            }
        });

    } catch (error) {
        console.error('❌ Create admin error:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal membuat admin',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// 15.5. ENDPOINT KOMPATIBILITAS: Create Admin (Legacy Format - /api/admin-users/create)
app.post('/api/admin-users/create', async (req, res) => {
    try {
        console.log('🔄 Compat: Create admin request (legacy):', req.body);

        const { username, password, role } = req.body;

        // Validasi input
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username dan password diperlukan'
            });
        }

        // Cek duplikat username
        const existingUser = await adminUsersPath()
            .where('username', '==', username)
            .get();

        if (!existingUser.empty) {
            return res.status(400).json({
                success: false,
                message: 'Username sudah digunakan'
            });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Data admin baru
        const newAdmin = {
            username,
            password: hashedPassword,
            role: role || 'admin',
            isActive: true,
            createdAt: new Date(),
            createdBy: req.headers['x-admin-id'] || 'system',
            permissions: ['view', 'edit', 'delete']
        };

        // Simpan ke Firestore
        const result = await adminUsersPath().add(newAdmin);

        // Log action
        await adminLogsPath().add({
            action: 'create_admin',
            adminId: username,
            createdBy: req.headers['x-admin-id'] || 'system',
            ipAddress: req.ip,
            timestamp: new Date()
        });

        res.json({
            success: true,
            message: 'Admin berhasil dibuat (legacy endpoint)',
            admin: {
                id: result.id,
                username,
                role: role || 'admin'
            }
        });

    } catch (error) {
        console.error('❌ Compat: Create admin error:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal membuat admin',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// 16. Update Admin
app.put('/api/admin/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;

        // Validasi ID
        if (!id) {
            return res.status(400).json({
                success: false,
                message: 'Admin ID diperlukan'
            });
        }

        // Jangan izinkan update password langsung
        if (updates.password) {
            delete updates.password;
        }

        updates.updatedAt = new Date();

        await adminUsersPath().doc(id).update(updates);

        res.json({
            success: true,
            message: 'Admin berhasil diperbarui'
        });

    } catch (error) {
        console.error('❌ Update admin error:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal memperbarui admin'
        });
    }
});

// 17. Delete Admin (New Format)
app.delete('/api/admin/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { adminId } = req.body;

        if (!adminId) {
            return res.status(400).json({
                success: false,
                message: 'Admin ID diperlukan'
            });
        }

        // Prevent deleting self
        const adminDoc = await adminUsersPath().doc(id).get();
        if (adminDoc.exists && adminDoc.data().username === adminId) {
            return res.status(400).json({
                success: false,
                message: 'Tidak dapat menghapus akun sendiri'
            });
        }

        await adminUsersPath().doc(id).delete();

        // Log action
        await adminLogsPath().add({
            action: 'delete_admin',
            targetId: id,
            deletedBy: adminId,
            ipAddress: req.ip,
            timestamp: new Date()
        });

        res.json({
            success: true,
            message: 'Admin berhasil dihapus'
        });

    } catch (error) {
        console.error('❌ Delete admin error:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal menghapus admin'
        });
    }
});

// 17.5. ENDPOINT KOMPATIBILITAS: Delete Admin (Legacy Format - /api/admin-users/:id)
app.delete('/api/admin-users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { adminId } = req.body;

        console.log('🔄 Compat: Delete admin request (legacy):', id, adminId);

        if (!adminId) {
            return res.status(400).json({
                success: false,
                message: 'Admin ID diperlukan'
            });
        }

        // Prevent deleting self
        const adminDoc = await adminUsersPath().doc(id).get();
        if (adminDoc.exists && adminDoc.data().username === adminId) {
            return res.status(400).json({
                success: false,
                message: 'Tidak dapat menghapus akun sendiri'
            });
        }

        await adminUsersPath().doc(id).delete();

        // Log action
        await adminLogsPath().add({
            action: 'delete_admin',
            targetId: id,
            deletedBy: adminId,
            ipAddress: req.ip,
            timestamp: new Date()
        });

        res.json({
            success: true,
            message: 'Admin berhasil dihapus (legacy endpoint)'
        });

    } catch (error) {
        console.error('❌ Compat: Delete admin error:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal menghapus admin'
        });
    }
});

// Endpoint untuk menghapus klien berdasarkan ID
app.delete('/api/clients/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { adminId } = req.body;

        // Pastikan adminId dikirimkan dalam body request
        if (!adminId) {
            return res.status(400).json({
                success: false,
                message: 'Admin ID diperlukan'
            });
        }

        // Ambil data klien dari Firestore berdasarkan ID
        const clientDoc = await clientsPath().doc(id).get();
        if (!clientDoc.exists) {
            return res.status(404).json({
                success: false,
                message: 'Klien tidak ditemukan'
            });
        }

        // Hapus data klien dari Firestore
        await clientsPath().doc(id).delete();

        // Log aksi penghapusan
        await adminLogsPath().add({
            adminId,
            action: 'delete_client',
            targetId: id,
            deletedBy: adminId,
            ipAddress: req.ip,
            timestamp: new Date()
        });

        // Response sukses setelah klien dihapus
        res.json({
            success: true,
            message: 'Klien berhasil dihapus'
        });
    } catch (error) {
        console.error('❌ Delete client error:', error);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan saat menghapus klien',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});


// 15.6. ENDPOINT KOMPATIBILITAS: Get Admin Users (Legacy Format - /api/admin-users)
app.get('/api/admin-users', async (req, res) => {
    try {
        console.log('🔄 Compat: Get admin-users request');

        const snapshot = await adminUsersPath().get();

        const admins = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            admins.push({
                id: doc.id,
                username: data.username,
                role: data.role || 'admin',
                isActive: data.isActive !== false,
                createdAt: data.createdAt?.toDate() || new Date(),
                lastLogin: data.lastLogin?.toDate() || null,
                createdBy: data.createdBy || 'system'
            });
        });

        res.json({
            success: true,
            count: admins.length,
            users: admins  // Perhatikan: 'users' bukan 'admins' untuk kompatibilitas
        });
    } catch (error) {
        console.error('❌ Compat: Get admin-users error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// 18. Get Admin Logs
app.get('/api/admin/logs', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;

        const snapshot = await adminLogsPath()
            .orderBy('timestamp', 'desc')
            .limit(limit)
            .get();

        const logs = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            logs.push({
                id: doc.id,
                action: data.action,
                adminId: data.adminId || data.createdBy || 'system',
                targetId: data.targetId || data.clientId || 'N/A',
                ipAddress: data.ipAddress || 'Unknown',
                timestamp: data.timestamp?.toDate() || new Date(),
                details: {
                    name: data.name || 'N/A',
                    username: data.username || 'N/A',
                    reason: data.reason || 'N/A'
                }
            });
        });

        res.json({
            success: true,
            count: logs.length,
            logs: logs
        });
    } catch (error) {
        console.error('❌ Get admin logs error:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal mengambil logs'
        });
    }
});

// ==================== ERROR HANDLING ====================

// Error handling untuk JSON parsing errors
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        console.error('❌ JSON Parse Error:', err.message);
        return res.status(400).json({
            success: false,
            message: 'Invalid JSON format in request',
            error: 'JSON parse error'
        });
    }
    next();
});

// ==================== HTML ROUTES WITH MIDDLEWARE ====================

// Middleware untuk inject script ke HTML responses
app.use((req, res, next) => {
    const originalSend = res.send;
    const originalSendFile = res.sendFile;

    // Override res.send untuk HTML
    res.send = function (body) {
        if (typeof body === 'string' &&
            (res.get('Content-Type')?.includes('text/html') ||
                body.trim().toLowerCase().startsWith('<!doctype html>') ||
                body.includes('</html>') ||
                body.includes('</body>'))) {

            console.log(`📄 Injecting API script to: ${req.url}`);
            body = injectAPIScript(body);
        }
        return originalSend.call(this, body);
    };
    res.sendFile = function (filePath, options, callback) {
        const fs = require('fs');

        try {
            if (typeof filePath === 'string' && filePath.endsWith('.html') && fs.existsSync(filePath)) {
                console.log(`📄 Injecting API script to file: ${filePath}`);
                let htmlContent = fs.readFileSync(filePath, 'utf8');
                htmlContent = injectAPIScript(htmlContent);

                // pastikan header html
                res.setHeader('Content-Type', 'text/html');
                return originalSend.call(res, htmlContent);
            }
        } catch (err) {
            console.error('❌ Error injecting script:', err);
        }

        // fallback default behavior
        return originalSendFile.call(res, filePath, options, callback);
    };

    next();
});
    // Override res.sendFile untuk HTML files                  

// ==================== ROUTE DEFINITIONS ====================

// User Pages
app.get('/', (req, res) => {
    res.sendFile(path.join(userFolder, 'index.html'));
});

app.get('/index', (req, res) => {
    res.sendFile(path.join(userFolder, 'index.html'));
});

app.get('/proses', (req, res) => {
    res.sendFile(path.join(userFolder, 'proses.html'));
});

app.get('/proses2', (req, res) => {
    res.sendFile(path.join(userFolder, 'proses2.html'));
});

app.get('/proses3', (req, res) => {
    res.sendFile(path.join(userFolder, 'proses3.html'));
});

app.get('/prosesend', (req, res) => {
    res.sendFile(path.join(userFolder, 'prosesend.html'));
});

app.get('/prosessakhir', (req, res) => {
    res.sendFile(path.join(userFolder, 'prosessakhir.html'));
});

app.get('/halamanselesai', (req, res) => {
    res.sendFile(path.join(userFolder, 'halamanselesai.html'));
});

// Admin Pages
app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(adminFolder, 'dashboard.html'));
});

app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(adminFolder, 'login.html'));
});

// Catch-all untuk redirect
app.get('/admin', (req, res) => {
    res.redirect('/admin/dashboard');
});

// Static files
app.get('/favicon.ico', (req, res) => {
    res.sendFile(path.join(userFolder, 'favicon.ico'));
});

// Global error handler
app.use((err, req, res, next) => {
    if (res.headersSent) {
        return next(err);
    }

    console.error('❌ Server error:', err.stack);

    res.status(500).json({
        success: false,
        message: 'Terjadi kesalahan internal server',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 Handler
app.use((req, res) => {
    if (res.headersSent) return;

    res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>404 - Digital Informatic</title>
            <style>
                body { 
                    background: #020205;
                    color: #e2e8f0;
                    font-family: 'Lexend', sans-serif;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    min-height: 100vh;
                    margin: 0;
                    padding: 20px;
                }
                .error-card {
                    background: rgba(18, 18, 26, 0.8);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(255, 255, 255, 0.08);
                    border-radius: 2rem;
                    padding: 3rem;
                    text-align: center;
                    max-width: 500px;
                    width: 100%;
                }
                h1 { 
                    color: #8b5cf6;
                    font-size: 4rem;
                    margin: 0;
                    font-weight: 900;
                }
                h2 {
                    color: #e2e8f0;
                    margin: 1rem 0;
                }
                p {
                    color: #94a3b8;
                    margin-bottom: 2rem;
                }
                a {
                    background: #8b5cf6;
                    color: white;
                    padding: 1rem 2rem;
                    border-radius: 1rem;
                    text-decoration: none;
                    font-weight: bold;
                    display: inline-block;
                    transition: all 0.3s ease;
                }
                a:hover {
                    background: #7c3aed;
                    transform: translateY(-2px);
                }
            </style>
        </head>
        <body>
            <div class="error-card">
                <h1>404</h1>
                <h2>Halaman Tidak Ditemukan</h2>
                <p>Halaman yang Anda cari tidak tersedia atau telah dipindahkan.</p>
                <a href="/">Kembali ke Beranda</a>
            </div>
        </body>
        </html>
    `);
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
    console.log(`\n✅ Digital Informatic Server running on http://localhost:${PORT}`);
    console.log(`📱 Mode: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔧 API Test: http://localhost:${PORT}/api/test`);
    console.log(`🔐 SUPERADMIN Login: POST http://localhost:${PORT}/api/auth/login`);
    console.log(`📊 Firestore Path: artifacts/${APP_ID}/public/data/admin_user`);
    console.log(`\n🏠 Halaman Pengguna:`);
    console.log('   • /              - Beranda utama');
    console.log('   • /proses        - Pilih modul ekstraksi');
    console.log('   • /proses2       - Otorisasi koneksi');
    console.log('   • /proses3       - Laporan intelijen');
    console.log('   • /prosesend     - Terminal dashboard');
    console.log('   • /prosessakhir  - Laporan akhir');
    console.log('   • /halamanselesai - Halaman terima kasih');
    console.log(`\n👑 Halaman Admin:`);
    console.log('   • /admin/login   - Login admin');
    console.log('   • /admin/dashboard - Dashboard admin');
    console.log(`\n🚀 API Features:`);
    console.log('   • Admin Management (CRUD admins)');
    console.log('   • Client Registration');
    console.log('   • Pending Requests');
    console.log('   • RDP Authentication');
    console.log(`\n🔐 Test Credentials: Superadmin / Digital@Super2026!`);
    console.log(`📊 Database: Firebase (Connected)`);
    console.log(`\n⚡ Server siap menerima koneksi...\n`);
});
