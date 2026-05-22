import fetch from 'node-fetch';

export default async function handler(req, res) {
    const allowedOrigin = 'https://apptestsuppressed.xyz';
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    // 2. DATA EXTRACTION
    const { 
        email, 
        firstname, 
        lastname, 
        company, 
        jobtitle, 
        employment_type, 
        primary_building_segment, 
        address, 
        city, 
        state, 
        zip, 
        phone, 
        wishlist_products, 
        captchaToken, 
        hutk, 
        pageUri,
        b_username // Honeypot check
    } = req.body || {};

    // Server-side Honeypot Check
    if (b_username) {
        console.log("BLOCKING SUBMISSION - Honeypot triggered.");
        return res.status(403).json({ message: "Bot detected." });
    }
    
    let ipAddress = req.headers['x-real-ip'] || req.headers['x-forwarded-for'];
    
    if (ipAddress) {
        ipAddress = ipAddress.split(',')[0].trim();
    } else {
        ipAddress = req.socket.remoteAddress;
    }

    if (ipAddress && ipAddress.includes('::ffff:')) {
        ipAddress = ipAddress.split('::ffff:')[1];
    }

    try {
        // 3. GOOGLE VERIFY
        const googleVerify = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${process.env.GOOGLE_RECAPTCHA_SECRET}&response=${captchaToken}`
        });

        const captchaResult = await googleVerify.json();
        
        console.log("Raw reCAPTCHA Response:", JSON.stringify(captchaResult));

        if (!captchaResult.success || captchaResult.score < 0.5) {
            console.log(`BLOCKING SUBMISSION - Reason/Score:`, captchaResult.score ?? "Invalid Key/Token");
            return res.status(403).json({ 
                message: "Blocked by reCAPTCHA", 
                score: captchaResult.score,
                errors: captchaResult['error-codes'] || []
            });
        }

        console.log("ALLOWING SUBMISSION - Sending to HubSpot...");

        // 4. HUBSPOT SUBMIT
        const hsResponse = await fetch(`https://api.hsforms.com/submissions/v3/integration/submit/${process.env.HUBSPOT_PORTAL_ID}/${process.env.HUBSPOT_FORM_ID}`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                fields: [
                    { name: "email", value: email },
                    { name: "firstname", value: firstname },
                    { name: "lastname", value: lastname },
                    { name: "company", value: company }, // Maps to Company Name
                    { name: "jobtitle", value: jobtitle }, // Maps to Job Title
                    { name: "primary_employment_type", value: employment_type },
                    { name: "primary_building_segment", value: primary_building_segment },
                    { name: "address", value: address },
                    { name: "city", value: city },
                    { name: "hs_state_code", value: state },
                    { name: "zip", value: zip },
                    { name: "phone", value: phone },
                    { name: "wishlist_products", value: wishlist_products }
                ],
                context: { 
                    hutk, 
                    ipAddress, 
                    pageUri 
                }
            })
        });

        if (hsResponse.ok) {
            return res.status(200).json({ message: "Success" });
        } else {
            const errorData = await hsResponse.json();
            console.error("HubSpot Error Details:", JSON.stringify(errorData));
            return res.status(500).json({ message: "HubSpot Error", details: errorData });
        }

    } catch (error) {
        return res.status(500).json({ message: "Server Error", error: error.message });
    }
}
