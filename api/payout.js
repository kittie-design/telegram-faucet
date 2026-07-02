import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

// Initialize Supabase
const supabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  // Only allow POST requests for security
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { userId, amount } = req.body;
  
  // Get IP address from the request header (provided by Vercel)
  const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  try {
    // 1. FRAUD CHECK (VPN/Proxy Detection)
    const ipqsUrl = `https://www.ipqualityscore.com/api/json/ip/${process.env.IPQS_API_KEY}/${ipAddress}?strictness=1`;
    const ipResponse = await fetch(ipqsUrl);
    const ipData = await ipResponse.json();

    if (ipData.proxy === true || ipData.vpn === true || ipData.tor === true) {
      return res.status(403).json({ error: "Fraud Alert: VPN/Proxy detected. Access denied." });
    }

    // 2. DATABASE ACTION
    // We insert the transaction. If the user doesn't exist, you might need 
    // a separate check or an 'upsert' logic depending on your needs.
    const { error } = await supabase
      .from('transactions')
      .insert({ user_id: userId, amount: amount, type: 'ad_view' });

    if (error) throw error;

    return res.status(200).json({ success: true, message: "Valid user, transaction complete." });

  } catch (error) {
    return res.status(403).json({ error: error.message });
  }
}
