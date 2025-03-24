// Import required modules
const express = require('express');
const mysql = require('mysql2/promise');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Initialize Express app
const app = express();
app.use(cors());
app.use(bodyParser.json());

// Global variables for QPay authentication token
let authToken = null;
let tokenExpiration = 0;
const payments = new Map();
const invoiceToPaymentMap = new Map();

// Secret key for JWT - CHANGE THIS IN PRODUCTION TO A SECURE VALUE!
const JWT_SECRET = 'your-secret-key';

// MySQL connection pool setup
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'app_user',
    password: process.env.DB_PASSWORD || 'SecurePass123!',
    database: process.env.DB_NAME || 'promo_tracker',
    connectionLimit: 10
});

// Middleware to verify admin JWT token
const authenticateAdmin = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.adminId = decoded.adminId;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Middleware to verify promo codes
const verifyPromoCode = async (req, res, next) => {
    const { promoCode } = req.body;
    if (!promoCode) {
        req.discount = 0;
        return next();
    }
    try {
        const [rows] = await pool.execute(
            'SELECT * FROM promo_codes WHERE promo_code = ? AND is_active = TRUE',
            [promoCode.toUpperCase()]
        );
        if (rows.length === 0) {
            req.discount = 0;
            return next();
        }
        req.discount = rows[0].discount_percentage;
        req.promoCode = rows[0].promo_code;
        req.promoId = rows[0].promo_id;
        next();
    } catch (error) {
        console.error('Promo code verification error:', error);
        req.discount = 0;
        next();
    }
};

// Function to get QPay authentication token
const getAuthToken = async () => {
    const now = Math.floor(Date.now() / 1000);
    if (authToken && now < tokenExpiration) {
        return authToken;
    }
    try {
        const response = await axios.post(
            'https://merchant.qpay.mn/v2/auth/token',
            {},
            {
                headers: {
                    'Authorization': `Basic ${Buffer.from(`${process.env.QPAY_USER}:${process.env.QPAY_PASS}`).toString('base64')}`
                }
            }
        );
        authToken = response.data.access_token;
        tokenExpiration = now + response.data.expires_in - 60;
        return authToken;
    } catch (error) {
        console.error('Authentication failed:', error.response?.data || error.message);
        throw error;
    }
};

// Admin Login endpoint
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [admins] = await pool.execute('SELECT * FROM admins WHERE username = ?', [username]);
        if (admins.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const admin = admins[0];
        if (!bcrypt.compareSync(password, admin.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ adminId: admin.admin_id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Verify admin token
app.get('/api/admin/verify', authenticateAdmin, async (req, res) => {
    try {
        const [admins] = await pool.execute('SELECT * FROM admins WHERE admin_id = ?', [req.adminId]);
        if (admins.length === 0) {
            return res.status(404).json({ error: 'Admin not found' });
        }
        res.json({ name: admins[0].username });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Create Invoice endpoint
app.post('/api/create-invoice', verifyPromoCode, async (req, res) => {
    try {
        const token = await getAuthToken();
        const baseAmount = 1500;
        const discountAmount = baseAmount * (req.discount / 100);
        const finalAmount = baseAmount - discountAmount;

        const invoiceResponse = await axios.post(
            'https://merchant.qpay.mn/v2/invoice',
            {
                invoice_code: "ACADEMIA_MN_INVOICE",
                sender_invoice_no: Date.now().toString(),
                invoice_receiver_code: "terminal",
                invoice_description: `academiacareer${req.promoCode ? ` (Promo: ${req.promoCode})` : ''}`,
                sender_branch_code: "SALBARACADEMIA",
                amount: finalAmount,
                callback_url: "http://174.129.173.184:5000/api/payment-callback"
            },
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const invoiceId = invoiceResponse.data.invoice_id;
        payments.set(invoiceId, {
            status: 'PENDING',
            details: null,
            verified: false,
            promoCode: req.promoCode,
            promoId: req.promoId,
            customerEmail: req.body.email
        });

        console.log('Invoice created:', invoiceResponse.data);
        res.json({
            ...invoiceResponse.data,
            originalAmount: baseAmount,
            discountApplied: discountAmount,
            finalAmount: finalAmount
        });
    } catch (error) {
        console.error('Invoice creation failed:', error.response?.data || error.message);
        res.status(500).json({
            error: 'Invoice creation failed',
            details: error.response?.data || error.message
        });
    }
});

// Callback handler for QPay
app.get('/api/payment-callback', async (req, res) => {
    const { qpay_payment_id } = req.query;
    if (!qpay_payment_id) {
        return res.status(400).json({ error: 'Payment ID is required' });
    }
    try {
        const token = await getAuthToken();
        const paymentInfo = await axios.get(
            `https://merchant.qpay.mn/v2/payment/${qpay_payment_id}`,
            { headers: { Authorization: `Bearer ${token}` } }
        );

        const invoiceId = paymentInfo.data.object_id;
        const paymentData = payments.get(invoiceId);

        if (paymentInfo.data.payment_status === 'PAID' && paymentData?.promoId) {
            await pool.execute(
                'INSERT INTO promo_usage (promo_id, customer_email) VALUES (?, ?)',
                [paymentData.promoId, paymentData.customerEmail || 'unknown@example.com']
            );
        }

        payments.set(qpay_payment_id, {
            status: paymentInfo.data.payment_status,
            details: paymentInfo.data,
            verified: true
        });
        invoiceToPaymentMap.set(invoiceId, qpay_payment_id);

        console.log('Callback received:', paymentInfo.data);
        res.status(200).send('SUCCESS');
    } catch (error) {
        console.error('Callback processing failed:', error.response?.data || error.message);
        res.status(500).json({ error: 'Callback processing failed' });
    }
});

// Payment status endpoint
app.get('/api/payment-status/:id', async (req, res) => {
    const { id } = req.params;
    if (!id) {
        return res.status(400).json({ error: 'ID is required' });
    }
    console.log(`Checking payment status for ID: ${id}`);
    try {
        let payment = payments.get(id);
        let paymentId = id;

        if (invoiceToPaymentMap.has(id)) {
            paymentId = invoiceToPaymentMap.get(id);
            payment = payments.get(paymentId);
            console.log(`Mapped invoice_id ${id} to payment_id ${paymentId}`);
        }

        if (!payment || !payment.verified) {
            const token = await getAuthToken();
            console.log(`Querying QPay with object_id: ${id}`);
            const checkResponse = await axios.post(
                'https://merchant.qpay.mn/v2/payment/check',
                {
                    object_type: 'INVOICE',
                    object_id: id,
                    offset: { page_number: 1, page_limit: 100 }
                },
                { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
            );

            console.log('QPay check response:', checkResponse.data);

            if (checkResponse.data.count > 0) {
                const paymentInfo = checkResponse.data.rows[0];
                paymentId = paymentInfo.payment_id;
                payments.set(paymentId, {
                    status: paymentInfo.payment_status,
                    details: paymentInfo,
                    verified: true
                });
                invoiceToPaymentMap.set(id, paymentId);
                payment = payments.get(paymentId);
            } else {
                payment = { status: 'PENDING', details: null };
            }
        }

        console.log('Payment status:', payment);
        res.json(payment || { status: 'PENDING', details: null });
    } catch (error) {
        console.error('Payment status check failed:', error.response?.data || error.message);
        res.status(500).json({ error: 'Payment verification failed', details: error.response?.data });
    }
});

// Promo code stats endpoint (admin only)
app.get('/api/promo/stats', authenticateAdmin, async (req, res) => {
    try {
        const [stats] = await pool.execute(`
            SELECT 
                u.username,
                pc.promo_code,
                pc.discount_percentage,
                COUNT(pu.usage_id) as usage_count,
                COUNT(DISTINCT pu.customer_email) as unique_customers
            FROM promo_codes pc
            LEFT JOIN promo_usage pu ON pc.promo_id = pu.promo_id
            JOIN users u ON pc.user_id = u.user_id
            GROUP BY pc.promo_id, u.username, pc.promo_code, pc.discount_percentage
            ORDER BY usage_count DESC
        `);
        res.json(stats);
    } catch (error) {
        console.error('Promo stats error:', error);
        res.status(500).json({ error: 'Failed to fetch promo statistics' });
    }
});

// Create promo code (admin only)
app.post('/api/promo/create', authenticateAdmin, async (req, res) => {
    const { promo_code, user_id, discount_percentage } = req.body;
    if (!promo_code || !user_id || !discount_percentage) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        await pool.execute(
            'INSERT INTO promo_codes (promo_code, user_id, discount_percentage, is_active) VALUES (?, ?, ?, TRUE)',
            [promo_code.toUpperCase(), user_id, discount_percentage]
        );
        res.status(201).json({ message: 'Promo code created successfully' });
    } catch (error) {
        console.error('Create promo error:', error);
        res.status(500).json({ error: 'Failed to create promo code' });
    }
});

// List promos (admin only)
app.get('/api/promo/list', authenticateAdmin, async (req, res) => {
    try {
        const [promos] = await pool.execute('SELECT * FROM promo_codes WHERE is_active = TRUE');
        res.json(promos);
    } catch (error) {
        console.error('List promos error:', error);
        res.status(500).json({ error: 'Failed to fetch promos' });
    }
});

// Modify promo (admin only)
app.put('/api/promo/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { promo_code, user_id, discount_percentage } = req.body;
    if (!promo_code || !user_id || !discount_percentage) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        const [result] = await pool.execute(
            'UPDATE promo_codes SET promo_code = ?, user_id = ?, discount_percentage = ? WHERE promo_id = ?',
            [promo_code.toUpperCase(), user_id, discount_percentage, id]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Promo code not found' });
        }
        res.json({ message: 'Promo updated successfully' });
    } catch (error) {
        console.error('Modify promo error:', error);
        res.status(500).json({ error: 'Failed to update promo' });
    }
});

// Delete promo code (admin only)
app.delete('/api/promo/:code', authenticateAdmin, async (req, res) => {
    const { code } = req.params;
    try {
        const [result] = await pool.execute(
            'UPDATE promo_codes SET is_active = FALSE WHERE promo_code = ?',
            [code.toUpperCase()]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Promo code not found' });
        }
        res.json({ message: 'Promo code deactivated successfully' });
    } catch (error) {
        console.error('Delete promo error:', error);
        res.status(500).json({ error: 'Failed to delete promo code' });
    }
});

// Payment info endpoint (admin only)
app.get('/api/payments', authenticateAdmin, async (req, res) => {
    try {
        const [payments] = await pool.execute(`
            SELECT 
                pu.customer_email,
                pc.promo_code,
                pu.used_at,
                u.gender,
                u.age,
                u.name,
                u.game1,
                u.game2,
                u.game3
            FROM promo_usage pu
            LEFT JOIN promo_codes pc ON pu.promo_id = pc.promo_id
            LEFT JOIN users u ON pu.customer_email = u.email
            ORDER BY pu.used_at DESC
        `);
        res.json(payments);
    } catch (error) {
        console.error('Payment info error:', error);
        res.status(500).json({ error: 'Failed to fetch payment info' });
    }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));