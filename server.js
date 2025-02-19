// server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Add these at the top
let authToken = null;
let tokenExpiration = 0;


// Updated getAuthToken function
const getAuthToken = async () => {
  const now = Math.floor(Date.now() / 1000);
  
  // Reuse token if still valid
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

    // Store token and expiration
    authToken = response.data.access_token;
    tokenExpiration = now + response.data.expires_in - 60; // 1 minute buffer
    return authToken;
  } catch (error) {
    console.error('Authentication failed:', error.response?.data || error.message);
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
        invoice_code: "ACADEMIA_MN_INVOICE",
        sender_invoice_no: Date.now().toString(), // Unique invoice number
        invoice_receiver_code: "terminal",
        invoice_description: "academiacareer",
        sender_branch_code: "SALBARACADEMIA",
        amount: 1500,
        callback_url: "http://174.129.173.184:5000/api/payment-callback"
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    console.log('Invoice created:', invoiceResponse.data); // Log the response
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
// Updated callback handler
app.get('/api/payment-status/:paymentId', async (req, res) => {
  try {
    const payment = payments.get(req.params.paymentId);
    
    if (!qpay_payment_id) {
      return res.status(400).json({ error: 'Missing payment ID' });
    }

    // Verify payment status
    const token = await getAuthToken();
    const paymentInfo = await axios.get(
      `https://merchant.qpay.mn/v2/payment/${req.params.paymentId}`, // Use payment ID
      { headers: { Authorization: `Bearer ${token}` } }
    );

    // Store using payment ID as the key
    payments.set(qpay_payment_id, { 
      status: paymentInfo.data.payment_status,
      details: paymentInfo.data,
      verified: true
    });

    res.status(200).send('SUCCESS');
  } catch (error) {
    if (error.response?.status === 400) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    res.status(500).json({ error: 'Payment verification failed' });
  }
});

app.get('/api/payment-status/:invoiceId', async (req, res) => {
  try {
    const payment = payments.get(req.params.invoiceId);
    
    // If no callback received yet, verify directly
    if (!payment || !payment.verified) {
      const token = await getAuthToken();
      const paymentInfo = await axios.get(
        `https://merchant.qpay.mn/v2/payment/${req.params.invoiceId}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      // Update storage
      payments.set(req.params.invoiceId, {
        status: paymentInfo.data.payment_status,
        details: paymentInfo.data,
        verified: true
      });
    }

    console.log('Payment status:', payments.get(req.params.invoiceId)); // Log the status
    res.json(payments.get(req.params.invoiceId) || { 
      status: 'PENDING', 
      details: null 
    });
  } catch (error) {
    console.error('Payment status check failed:', error);
    res.status(500).json({ error: 'Payment verification failed' });
  }
});

//seventh changes

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));