const express = require('express');
const mysql = require('mysql2/promise');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs').promises;
const FormData = require('form-data');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));

let authToken = null;
let tokenExpiration = 0;
const payments = new Map();
const invoiceToPaymentMap = new Map();

const upload = multer({ dest: 'uploads/' });
const MAILGUN_API_KEY = process.env.MAILGUN_API_KEY;
const MAILGUN_DOMAIN = process.env.MAILGUN_DOMAIN || 'mail.academia.mn';
const MAILGUN_API_URL = 'https://api.mailgun.net/v3';

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'app_user',
    password: process.env.DB_PASSWORD || 'SecurePass123!',
    database: process.env.DB_NAME || 'promo_tracker',
    connectionLimit: 10
});

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

const getAuthToken = async () => {
    const now = Math.floor(Date.now() / 1000);
    if (authToken && now < tokenExpiration) return authToken;
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

app.post('/api/create-invoice', verifyPromoCode, async (req, res) => {
  try {
    const token = await getAuthToken();
    const baseAmount = 1500; // Aligned with frontend
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
      customerEmail: req.body.email,
      pdfData: req.body.pdfData // Store base64 PDF
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

app.get('/api/payment-callback', async (req, res) => {
    const { qpay_payment_id } = req.query;
    if (!qpay_payment_id) return res.status(400).json({ error: 'Payment ID is required' });
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

const sendPdfEmail = async (email, pdfBuffer) => {
    try {
        const form = new FormData();
        form.append('from', `${MAILGUN_DOMAIN} <no-reply@${MAILGUN_DOMAIN}>`);
        form.append('to', email);
        form.append('subject', 'Таны Мэргэжил сонголтын репорт');
        form.append('text', 'Хавсаргасан PDF document-ийг татаж авна уу!');
        form.append('attachment', pdfBuffer, {
            filename: 'report.pdf',
            contentType: 'application/pdf'
        });

        const response = await axios.post(
            `${MAILGUN_API_URL}/${MAILGUN_DOMAIN}/messages`,
            form,
            {
                headers: {
                    'Authorization': `Basic ${Buffer.from(`api:${MAILGUN_API_KEY}`).toString('base64')}`,
                    ...form.getHeaders()
                }
            }
        );

        console.log('Email sent:', response.data.id);
    } catch (error) {
        console.error('Error sending email:', error.response?.data || error.message);
        throw error;
    }
};

app.get('/api/payment-status/:id', async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ error: 'ID is required' });
  console.log(`Checking payment status for ID: ${id}`);
  try {
    let payment = payments.get(id);
    let paymentId = id;

    if (invoiceToPaymentMap.has(id)) {
      paymentId = invoiceToPaymentMap.get(id);
      payment = payments.get(paymentId);
    }

    if (!payment || !payment.verified) {
      const token = await getAuthToken();
      const checkResponse = await axios.post(
        'https://merchant.qpay.mn/v2/payment/check',
        { object_type: 'INVOICE', object_id: id, offset: { page_number: 1, page_limit: 100 } },
        { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
      );

      if (checkResponse.data.count > 0) {
        const paymentInfo = checkResponse.data.rows[0];
        paymentId = paymentInfo.payment_id;
        payments.set(paymentId, {
          status: paymentInfo.payment_status,
          details: paymentInfo,
          verified: true,
          pdfData: payments.get(id)?.pdfData // Preserve PDF data
        });
        invoiceToPaymentMap.set(id, paymentId);
        payment = payments.get(paymentId);
      } else {
        payment = { status: 'PENDING', details: null };
      }
    }

    // Only send email and process PDF for paid customers
    if (payment.status === 'PAID' && payment.details && payment.pdfData) {
      const { customerEmail, pdfData } = payments.get(id);
      const pdfBuffer = Buffer.from(pdfData, 'base64'); // Real PDF from frontend
      await sendPdfEmail(customerEmail || 'unknown@example.com', pdfBuffer);
      console.log(`PDF email sent to ${customerEmail} for invoice ${id}`);
    }

    res.json(payment || { status: 'PENDING', details: null });
  } catch (error) {
    console.error('Payment status check failed:', error.response?.data || error.message);
    res.status(500).json({ error: 'Payment verification failed', details: error.response?.data });
  }
});
// Optional manual testing endpoint
app.post('/api/send-pdf', upload.single('pdf'), async (req, res) => {
    const { email } = req.body;
    const pdfPath = req.file?.path;

    if (!email || !pdfPath) return res.status(400).json({ error: 'Email and PDF are required' });

    try {
        const pdfBuffer = await fs.readFile(pdfPath);
        await sendPdfEmail(email, pdfBuffer);
        await fs.unlink(pdfPath);
        res.status(200).send('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).send(error.toString());
    }
});

app.listen(5000, () => console.log('Payment and Mail server running on port 5000'));