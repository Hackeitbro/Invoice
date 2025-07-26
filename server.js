const express = require('express');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin (add your service account key)
const serviceAccount = require('./firebase-service-account.json');
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// Initialize Razorpay with LIVE credentials
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_live_nkszfAsN6gyszW',
    key_secret: process.env.RAZORPAY_KEY_SECRET || '3zFrNXjCvc97asKob3KRW0Qy'
});

console.log('✅ Razorpay LIVE mode initialized with key:', 'rzp_live_nkszfAsN6gyszW');

// Middleware to verify Firebase token
const verifyFirebaseToken = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Create Razorpay Order
app.post('/api/create-subscription-order', verifyFirebaseToken, async (req, res) => {
    try {
        const { planName, amount, currency = 'INR', userId, userEmail } = req.body;

        // Validate input
        if (!planName || !amount || !userId || !userEmail) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Verify user matches token
        if (req.user.uid !== userId) {
            return res.status(403).json({ error: 'User ID mismatch' });
        }

        // ADD THIS NEW CODE HERE:
// Test mode validation - ensure amount is 1 rupee (100 paise)
if (amount !== 100) {
    console.log('⚠️ TEST MODE: Expected amount 100 paise (₹1), received:', amount);
}
        // Create Razorpay order
        const orderOptions = {
            amount: parseInt(amount), // Amount in paise
            currency: currency,
            receipt: `rcpt_${Date.now().toString().slice(-8)}`,
            notes: {
                planName: planName,
                userId: userId,
                userEmail: userEmail,
                createdAt: new Date().toISOString(),
                mode: 'LIVE'
            }
        };

        const order = await razorpay.orders.create(orderOptions);

        console.log('✅ LIVE Order created:', order.id);

        res.json({
            success: true,
            orderId: order.id,
            amount: order.amount,
            currency: order.currency
        });

    } catch (error) {
        console.error('❌ Order creation error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to create order',
            details: error.message
        });
    }
});

// Verify Payment
app.post('/api/verify-payment', verifyFirebaseToken, async (req, res) => {
    try {
        const {
            razorpay_order_id,
            razorpay_payment_id,
            razorpay_signature,
            planName,
            amount,
            duration,
            userId
        } = req.body;

        console.log('🔍 LIVE Payment verification request:', {
            razorpay_order_id,
            razorpay_payment_id,
            razorpay_signature: razorpay_signature ? 'present' : 'missing',
            planName,
            amount,
            duration,
            userId
        });

        // Validate input
        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
            console.log('❌ Missing payment details:', { razorpay_order_id, razorpay_payment_id, razorpay_signature });
            return res.status(400).json({ error: 'Missing payment details' });
        }

        // Verify user matches token
        if (req.user.uid !== userId) {
            console.log('❌ User ID mismatch:', { tokenUid: req.user.uid, bodyUserId: userId });
            return res.status(403).json({ error: 'User ID mismatch' });
        }

        // Create signature for verification using LIVE secret
        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const keySecret = process.env.RAZORPAY_KEY_SECRET || '3zFrNXjCvc97asKob3KRW0Qy';
        const expectedSignature = crypto
            .createHmac('sha256', keySecret)
            .update(body.toString())
            .digest('hex');

        console.log('🔐 LIVE Signature verification:', {
            body,
            expectedSignature,
            receivedSignature: razorpay_signature,
            match: expectedSignature === razorpay_signature
        });

        const isAuthentic = expectedSignature === razorpay_signature;

        if (isAuthentic) {
            // Payment verified successfully
            console.log('✅ LIVE PAYMENT VERIFIED:', razorpay_payment_id);

            res.json({
                success: true,
                message: 'Payment verified successfully',
                paymentId: razorpay_payment_id,
                mode: 'LIVE'
            });

        } else {
            console.warn('❌ Invalid payment signature:', {
                expected: expectedSignature,
                received: razorpay_signature
            });
            res.status(400).json({
                success: false,
                error: 'Payment verification failed - invalid signature'
            });
        }

    } catch (error) {
        console.error('❌ Payment verification error:', error);
        res.status(500).json({
            success: false,
            error: 'Payment verification failed',
            details: error.message
        });
    }
});

// Webhook endpoint for Razorpay events
app.post('/api/razorpay-webhook', express.raw({ type: 'application/json' }), (req, res) => {
    try {
        const secret = process.env.RAZORPAY_WEBHOOK_SECRET || 'your_webhook_secret';
        const signature = req.headers['x-razorpay-signature'];

        // Verify webhook signature
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(req.body)
            .digest('hex');

        if (signature === expectedSignature) {
            const event = JSON.parse(req.body);
            console.log('📧 LIVE Webhook event:', event.event, event.payload);

            // Handle different webhook events
            switch (event.event) {
                case 'payment.captured':
                    console.log('💰 LIVE Payment captured:', event.payload.payment.entity.id);
                    break;
                case 'payment.failed':
                    console.log('💥 LIVE Payment failed:', event.payload.payment.entity.id);
                    break;
                case 'subscription.activated':
                    console.log('🎉 LIVE Subscription activated:', event.payload.subscription.entity.id);
                    break;
                default:
                    console.log('📋 Unhandled webhook event:', event.event);
            }

            res.status(200).json({ received: true });
        } else {
            res.status(400).json({ error: 'Invalid webhook signature' });
        }

    } catch (error) {
        console.error('❌ Webhook error:', error);
        res.status(500).json({ error: 'Webhook processing failed' });
    }
});

// Validate user subscription
app.get('/api/validate-subscription/:userId', verifyFirebaseToken, async (req, res) => {
    try {
        const { userId } = req.params;

        // Verify user matches token
        if (req.user.uid !== userId) {
            return res.status(403).json({ error: 'User ID mismatch' });
        }

        res.json({
            success: true,
            message: 'Subscription validation endpoint ready',
            mode: 'LIVE'
        });

    } catch (error) {
        console.error('❌ Subscription validation error:', error);
        res.status(500).json({
            success: false,
            error: 'Subscription validation failed'
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        razorpay: 'LIVE MODE CONNECTED',
        mode: 'LIVE'
    });
});

// Test endpoint to verify live credentials
app.get('/api/test-live', (req, res) => {
    res.json({
        message: 'Live mode backend is running',
        keyId: 'rzp_live_nkszfAsN6gyszW',
        mode: 'LIVE',
        timestamp: new Date().toISOString()
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('❌ Unhandled error:', error);
    res.status(500).json({
        error: 'Internal server error',
        message: error.message,
        mode: 'LIVE'
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log('💳 Razorpay LIVE MODE integration ready!');
    console.log('🔑 Using Live Key ID: rzp_live_nkszfAsN6gyszW');
    console.log('⚠️  WARNING: LIVE MODE - Real money transactions enabled!');
});

module.exports = app;