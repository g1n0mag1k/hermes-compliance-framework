// netlify/functions/stripe-webhook.js
// Hermes Canary Pro — Stripe → Keygen license provisioning webhook
//
// Environment variables required (set in Netlify UI → Site → Environment variables):
//   STRIPE_SECRET_KEY          — sk_live_... (Stripe secret key)
//   STRIPE_WEBHOOK_SECRET      — whsec_...  (from Stripe Dashboard → Webhooks → signing secret)
//   KEYGEN_ACCOUNT_SLUG        — rogersandy90
//   KEYGEN_PRODUCT_ID          — 933323e7-e2f9-4ccb-9f13-b574cc38bf4e
//   KEYGEN_POLICY_ID           — b05916b2-3a72-4608-aeec-4246dd58e05d
//   KEYGEN_ADMIN_TOKEN         — your Keygen admin/product token (never the license key itself)
//   SENDGRID_API_KEY           — SG.... (or swap for any transactional email provider)
//   FROM_EMAIL                 — noreply@hermesrelay.dev
//
// Stripe product/price wired to this webhook:
//   Product ID:  prod_VN8iUDJpWsHQLh
//   Price ID:    price_1UMOR8BeC3pIIEz60aIADISI  ($29/month Per Repo)
//
// Events handled:
//   checkout.session.completed   → create Keygen license, email key to customer
//   customer.subscription.deleted → (optional) revoke Keygen license on cancellation

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const KEYGEN_BASE = "https://api.keygen.sh/v1";
const KEYGEN_ACCOUNT = process.env.KEYGEN_ACCOUNT_SLUG;
const KEYGEN_PRODUCT_ID = process.env.KEYGEN_PRODUCT_ID;
const KEYGEN_POLICY_ID = process.env.KEYGEN_POLICY_ID;
const KEYGEN_ADMIN_TOKEN = process.env.KEYGEN_ADMIN_TOKEN;
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL || "noreply@hermesrelay.dev";

// ─── Keygen helpers ───────────────────────────────────────────────────────────

async function createKeygenLicense({ customerEmail, stripeCustomerId, stripeSubscriptionId }) {
  const url = `${KEYGEN_BASE}/accounts/${KEYGEN_ACCOUNT}/licenses`;

  const body = {
    data: {
      type: "licenses",
      attributes: {
        name: `Hermes Canary Pro — ${customerEmail}`,
        metadata: {
          stripeCustomerId,
          stripeSubscriptionId,
          provisionedAt: new Date().toISOString(),
        },
      },
      relationships: {
        policy: {
          data: { type: "policies", id: KEYGEN_POLICY_ID },
        },
        // Scopes to the correct product — only licenses under this product
        // will pass validation when canary-action checks the policy ID.
        // The policy already belongs to the product; this is belt-and-suspenders.
        // Remove if your Keygen plan doesn't support the relationship directly.
      },
    },
  };

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${KEYGEN_ADMIN_TOKEN}`,
      "Content-Type": "application/vnd.api+json",
      Accept: "application/vnd.api+json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Keygen license creation failed ${response.status}: ${errBody}`);
  }

  const json = await response.json();
  const licenseId = json.data.id;
  const licenseKey = json.data.attributes.key;

  return { licenseId, licenseKey };
}

async function revokeLicense(licenseId) {
  const url = `${KEYGEN_BASE}/accounts/${KEYGEN_ACCOUNT}/licenses/${licenseId}`;
  const response = await fetch(url, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${KEYGEN_ADMIN_TOKEN}`,
      Accept: "application/vnd.api+json",
    },
  });
  if (!response.ok && response.status !== 404) {
    const errBody = await response.text();
    throw new Error(`Keygen license revocation failed ${response.status}: ${errBody}`);
  }
}

// Look up a Keygen license by Stripe subscription ID stored in metadata.
// Used for cancellation to find the license to revoke.
async function findLicenseBySubscriptionId(stripeSubscriptionId) {
  const url = `${KEYGEN_BASE}/accounts/${KEYGEN_ACCOUNT}/licenses?meta[stripeSubscriptionId]=${encodeURIComponent(stripeSubscriptionId)}&limit=1`;
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${KEYGEN_ADMIN_TOKEN}`,
      Accept: "application/vnd.api+json",
    },
  });
  if (!response.ok) return null;
  const json = await response.json();
  return json.data && json.data.length > 0 ? json.data[0].id : null;
}

// ─── Email helpers (SendGrid) ─────────────────────────────────────────────────

async function sendLicenseEmail({ toEmail, licenseKey, licenseId }) {
  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#1a1a1a">
  <img src="https://hermesrelay.dev/logo.png" alt="Hermes Relay" width="120" style="margin-bottom:24px">
  <h1 style="font-size:22px;margin-bottom:8px">Your Hermes Canary Pro license key</h1>
  <p style="color:#555;margin-bottom:24px">Thank you for subscribing. Copy the key below and add it as a <strong>KEYGEN_LICENSE_KEY</strong> secret in your GitHub repository.</p>

  <div style="background:#f4f4f5;border-radius:8px;padding:16px;font-family:monospace;font-size:15px;word-break:break-all;margin-bottom:24px">
    ${licenseKey}
  </div>

  <h2 style="font-size:16px;margin-bottom:12px">Quick start (2 steps)</h2>
  <ol style="color:#333;line-height:1.8">
    <li>Go to your repo → <strong>Settings → Secrets → Actions</strong></li>
    <li>Add two secrets:
      <ul>
        <li><code>KEYGEN_LICENSE_KEY</code> — paste the key above</li>
        <li><code>HERMES_SIGNING_KEY</code> — run <code>openssl rand -hex 32</code> and paste the output</li>
      </ul>
    </li>
  </ol>

  <p>Then create <code>.github/workflows/phi-canary.yml</code> using the template in the <a href="https://github.com/g1n0mag1k/hermes-canary-action#readme">README</a>.</p>

  <hr style="border:none;border-top:1px solid #e5e5e5;margin:32px 0">
  <p style="font-size:13px;color:#888">
    License ID: <code>${licenseId}</code><br>
    Questions? Email <a href="mailto:support@hermesrelay.dev">support@hermesrelay.dev</a>
  </p>
</body>
</html>
`;

  const response = await fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SENDGRID_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: toEmail }] }],
      from: { email: FROM_EMAIL, name: "Hermes Relay" },
      subject: "Your Hermes Canary Pro license key",
      content: [{ type: "text/html", value: html }],
    }),
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`SendGrid email failed ${response.status}: ${errBody}`);
  }
}

// ─── Main handler ─────────────────────────────────────────────────────────────

exports.handler = async (event) => {
  // Only accept POST
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  // Verify Stripe webhook signature
  const sig = event.headers["stripe-signature"];
  let stripeEvent;
  try {
    stripeEvent = stripe.webhooks.constructEvent(
      event.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error("Stripe signature verification failed:", err.message);
    return { statusCode: 400, body: `Webhook Error: ${err.message}` };
  }

  const eventType = stripeEvent.type;
  console.log(`Stripe event received: ${eventType}`);

  // ── checkout.session.completed → provision license ────────────────────────
  if (eventType === "checkout.session.completed") {
    const session = stripeEvent.data.object;

    // Only handle subscriptions (not one-time payments)
    if (session.mode !== "subscription") {
      return { statusCode: 200, body: "OK (non-subscription checkout ignored)" };
    }

    const customerEmail = session.customer_details?.email || session.customer_email;
    const stripeCustomerId = session.customer;
    const stripeSubscriptionId = session.subscription;

    if (!customerEmail) {
      console.error("No customer email in checkout session", session.id);
      return { statusCode: 400, body: "Missing customer email" };
    }

    console.log(`Provisioning license for ${customerEmail} (sub: ${stripeSubscriptionId})`);

    let licenseId, licenseKey;
    try {
      ({ licenseId, licenseKey } = await createKeygenLicense({
        customerEmail,
        stripeCustomerId,
        stripeSubscriptionId,
      }));
      console.log(`Keygen license created: ${licenseId} for ${customerEmail}`);
    } catch (err) {
      console.error("Keygen license creation error:", err.message);
      // Return 500 so Stripe retries — critical path
      return { statusCode: 500, body: "License provisioning failed" };
    }

    try {
      await sendLicenseEmail({ toEmail: customerEmail, licenseKey, licenseId });
      console.log(`License email sent to ${customerEmail}`);
    } catch (err) {
      // Don't return 500 — license was created, email failure shouldn't cause Stripe to retry
      // and double-provision. Log and alert manually.
      console.error("SendGrid email error (license already created):", err.message);
      // TODO: Add fallback alert (e.g. send to support@hermesrelay.dev with the key)
    }

    return { statusCode: 200, body: "OK" };
  }

  // ── customer.subscription.deleted → revoke license ────────────────────────
  if (eventType === "customer.subscription.deleted") {
    const subscription = stripeEvent.data.object;
    const stripeSubscriptionId = subscription.id;

    console.log(`Subscription cancelled: ${stripeSubscriptionId} — revoking Keygen license`);

    try {
      const licenseId = await findLicenseBySubscriptionId(stripeSubscriptionId);
      if (licenseId) {
        await revokeLicense(licenseId);
        console.log(`Keygen license revoked: ${licenseId}`);
      } else {
        console.warn(`No Keygen license found for subscription ${stripeSubscriptionId}`);
      }
    } catch (err) {
      console.error("License revocation error:", err.message);
      // Don't fail — Stripe shouldn't retry a cancellation event
    }

    return { statusCode: 200, body: "OK" };
  }

  // All other events — acknowledge and ignore
  return { statusCode: 200, body: "OK (event ignored)" };
};
