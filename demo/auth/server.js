const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = 'aegis-super-secret';

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Hardcoded mock authentication for demo purposes
    if (username === 'admin' && password === 'admin') {
        const token = jwt.sign({ user: username, role: 'admin' }, SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials. Use admin/admin' });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Auth service running on port ${PORT}`));
