JavaScript
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'llave_secreta_finanzas_2026';

// Autenticación
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });
  try {
    const decoded = jwt.decode(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
};

// Inicializador de Base de Datos
app.get('/init-db', async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        monthly_income DECIMAL(12, 2) DEFAULT 0,
        hourly_rate DECIMAL(8, 2) DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS transactions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL(12, 2) NOT NULL,
        merchant_name VARCHAR(255),
        type VARCHAR(20) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
    `);
    res.json({ message: 'Base de datos inicializada correctamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Auth Endpoints
app.post('/api/auth/register', async (req, res) => {
  const { email, password, monthlyIncome } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const hourly = (monthlyIncome || 0) / 160;
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, monthly_income, hourly_rate) VALUES ($1, $2, $3, $4) RETURNING id, email',
      [email, hash, monthlyIncome || 0, hourly]
    );
    const token = jwt.encode({ userId: result.rows[0].id }, JWT_SECRET);
    res.json({ token, user: result.rows[0] });
  } catch (err) {
    res.status(400).json({ error: 'El usuario ya existe' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (!result.rows.length) return res.status(400).json({ error: 'Usuario no encontrado' });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ error: 'Contraseña incorrecta' });
    const token = jwt.encode({ userId: user.id }, JWT_SECRET);
    res.json({ token, user: { id: user.id, email: user.email, monthlyIncome: user.monthly_income, hourlyRate: user.hourly_rate } });
  } catch (err) {
    res.status(500).json({ error: 'Error en servidor' });
  }
});

// Transacciones
app.get('/api/transactions', authenticate, async (req, res) => {
  const txs = await pool.query('SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC', [req.userId]);
  res.json(txs.rows);
});

app.post('/api/transactions', authenticate, async (req, res) => {
  const { amount, merchantName, type } = req.body;
  const result = await pool.query(
    'INSERT INTO transactions (user_id, amount, merchant_name, type) VALUES ($1, $2, $3, $4) RETURNING *',
    [req.userId, amount, merchantName, type]
  );
  res.json(result.rows[0]);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor activo en puerto ${PORT}`));