// server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Get Auth Token
const getAuthToken = async () => {
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
    return response.data.access_token;
  } catch (error) {
    console.error('Authentication failed:', error.response.data);
    throw error;
  }
};

// Create Invoice
app.post('/api/create-invoice', async (req, res) => {
  try {
    const token = await getAuthToken();
    
    const invoiceResponse = await axios.post(
      'https://merchant.qpay.mn/v2/invoice',
      {
        invoice_code: "ACADEMIA_INVOICE",
        sender_invoice_no: Date.now().toString(), // Unique invoice number
        invoice_receiver_code: "terminal",
        invoice_description: "academia81",
        sender_branch_code: "SALBARACADEMIA",
        amount: 1000,
        callback_url: "http://174.129.173.184:5000/api/payment-callback"
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );

    res.json(invoiceResponse.data);
  } catch (error) {
    console.error('Invoice creation failed:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Invoice creation failed',
      details: error.response?.data || error.message
    });
  }
});

// Add after your existing imports
const payments = new Map(); // Temporary storage, replace with DB in production

// Add these endpoints after your create-invoice route
// Callback Handler
app.get('/api/payment-callback', async (req, res) => {
  try {
    const { qpay_payment_id } = req.query;
    
    if (!qpay_payment_id) {
      return res.status(400).json({ error: 'Missing payment ID' });
    }

    const token = await getAuthToken();
    const paymentInfo = await axios.get(
      `https://merchant-sandbox.qpay.mn/v2/payment/${qpay_payment_id}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    // Update payment status in storage
    const { object_id, payment_status } = paymentInfo.data;
    payments.set(object_id, { 
      status: payment_status,
      details: paymentInfo.data 
    });

    res.status(200).send('SUCCESS');
  } catch (error) {
    console.error('Callback error:', error);
    res.status(500).send('Callback processing failed');
  }
});

// Payment Status Check
app.get('/api/payment-status/:invoiceId', (req, res) => {
  const payment = payments.get(req.params.invoiceId);
  res.json(payment || { status: 'PENDING', details: null });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));