const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// قاعدة البيانات المحلية للمستخدمين والسكربتات
const db = new sqlite3.Database('./vanta.db');

db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS instances (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, script_type TEXT, filename TEXT, status TEXT)");
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'vanta_secret_key_999',
    resave: false,
    saveUninitialized: false
}));

// تخزين العمليات الجارية (Processes)
const activeProcesses = {};

// --- مسارات المصادقة ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
            if (err) return res.status(400).json({ error: "المستخدم موجود مسبقاً" });
            res.json({ success: true });
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "بيانات الدخول غير صحيحة" });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: "كلمة المرور غير صحيحة" });
        
        req.session.userId = user.id;
        req.session.username = user.username;
        res.json({ success: true });
    });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- لوحة التحكم وإدارة السكربتات ---
app.get('/api/instances', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: "غير مصرح" });
    db.all("SELECT * FROM instances WHERE user_id = ?", [req.session.userId], (err, rows) => {
        res.json(rows || []);
    });
});

// زر New: إنشاء مثيل جديد لسكربت (Python أو Node.js)
app.post('/api/instances/new', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: "غير مصرح" });
    const { name, script_type, code } = req.body;
    
    const filename = `script_${req.session.userId}_${Date.now()}.${script_type === 'python' ? 'py' : 'js'}`;
    const filePath = path.join(__dirname, 'scripts', filename);
    
    if (!fs.existsSync(path.join(__dirname, 'scripts'))) {
        fs.mkdirSync(path.join(__dirname, 'scripts'));
    }
    
    fs.writeFileSync(filePath, code || (script_type === 'python' ? 'print("Vanta Python Active")' : 'console.log("Vanta Node Active");'));

    db.run("INSERT INTO instances (user_id, name, script_type, filename, status) VALUES (?, ?, ?, ?, ?)",
        [req.session.userId, name, script_type, filename, 'stopped'], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: this.lastID });
        }
    );
});

// تشغيل السكربت ومراقبة المخرجات
app.post('/api/instances/:id/start', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: "غير مصرح" });
    const instanceId = req.params.id;

    db.get("SELECT * FROM instances WHERE id = ? AND user_id = ?", [instanceId, req.session.userId], (err, inst) => {
        if (err || !inst) return res.status(404).json({ error: "المثيل غير موجود" });

        if (activeProcesses[instanceId]) {
            return res.json({ success: true, message: "السكربت يعمل بالفعل" });
        }

        const filePath = path.join(__dirname, 'scripts', inst.filename);
        const command = inst.script_type === 'python' ? 'python3' : 'node';

        const proc = spawn(command, [filePath]);
        activeProcesses[instanceId] = { proc, logs: [] };

        proc.stdout.on('data', (data) => {
            activeProcesses[instanceId].logs.push(data.toString());
        });

        proc.stderr.on('data', (data) => {
            activeProcesses[instanceId].logs.push(`[ERROR] ${data.toString()}`);
        });

        proc.on('close', (code) => {
            activeProcesses[instanceId].logs.push(`[INFO] Process exited with code ${code}`);
            delete activeProcesses[instanceId];
        });

        db.run("UPDATE instances SET status = 'running' WHERE id = ?", [instanceId]);
        res.json({ success: true });
    });
});

// إيقاف السكربت
app.post('/api/instances/:id/stop', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: "غير مصرح" });
    const instanceId = req.params.id;

    if (activeProcesses[instanceId]) {
        activeProcesses[instanceId].proc.kill();
        delete activeProcesses[instanceId];
    }

    db.run("UPDATE instances SET status = 'stopped' WHERE id = ?", [instanceId], () => {
        res.json({ success: true });
    });
});

// جلب السجلات الحية (Live Console Logs)
app.get('/api/instances/:id/logs', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: "غير مصرح" });
    const instanceId = req.params.id;
    const logs = activeProcesses[instanceId] ? activeProcesses[instanceId].logs.join('') : "العملية متوقفة حالياً.";
    res.json({ logs });
});

app.listen(PORT, () => {
    console.log(`[VantaPanel] Running on port ${PORT}`);
});
