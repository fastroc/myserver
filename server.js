const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

let authToken = null;
let tokenExpiration = 0;
const payments = new Map();
const invoiceToPaymentMap = new Map();

// Promo code server URL
const PROMO_SERVER_URL = 'http://localhost:5001';

// Get authentication token (keep your existing function)
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

// Middleware to verify promo code and apply discount
const verifyPromoCode = async (req, res, next) => {
    const { promoCode } = req.body;
    if (!promoCode) {
        req.discount = 0; // No discount if no promo code
        return next();
    }

    try {
        const response = await axios.get(`${PROMO_SERVER_URL}/api/promo/verify`, {
            params: { promoCode }
        });

        req.discount = response.data.discountPercentage || 0;
        req.promoCode = response.data.promoCode;
        next();
    } catch (error) {
        console.error('Promo code verification failed:', error.response?.data || error.message);
        req.discount = 0; // Default to no discount if verification fails
        next(); // Proceed anyway, treat as no promo code
    }
};

// Create Invoice with Promo Code Support
app.post('/api/create-invoice', verifyPromoCode, async (req, res) => {
    try {
        const token = await getAuthToken();
        const baseAmount = 1500; // Original price in MNT
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
            customerEmail: req.body.email // Store email for usage tracking
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

// Callback handler with promo usage tracking
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

        if (paymentInfo.data.payment_status === 'PAID' && paymentData?.promoCode) {
            // Record promo code usage
            await axios.post(`${PROMO_SERVER_URL}/api/promo/use`, {
                promoCode: paymentData.promoCode,
                customerEmail: paymentData.customerEmail || 'unknown@example.com'
            });
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
//Hey commit again! 888 f,kljdlkgjdkljfkldjfklsdjf lots of it

// Payment status endpoint (unchanged)
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));