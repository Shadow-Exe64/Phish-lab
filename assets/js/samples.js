/*!
 * Sample messages for Phish Lab. All names, numbers and domains are fictional
 * or reserved for documentation. `expect` is the verdict the engine should give
 * (checked by tests/analyzer.test.js).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PhishSamples = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return [
    {
      id: 'ms-alert', group: 'Phishing', title: 'Microsoft account alert (mass phishing)', expect: 'malicious',
      text: `From: Microsoft Support <support@logins-updates.com>
Reply-To: helpdesk@ms-account-recovery.net
Subject: FW: Urgent: Your Account Security Alert
Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=logins-updates.com; dkim=none; dmarc=fail

Dear Customer,

We detected unusual sign-in activity on your Microsoft account. Your account will be suspended within 24 hours unless you verify your identity.

Verify your account now: https://microsoft-account-verify.logins-updates.com/signin

Security_Update_2024.iso is attached with the required patch.

Microsoft Account Team`,
    },
    {
      id: 'ceo-wire', group: 'Phishing', title: 'CEO wire transfer (BEC / whaling)', expect: 'malicious',
      text: `From: CEO - STRICTLY CONFIDENTIAL <ceo.urgent@executive-update.com>
Subject: IMMEDIATE ACTION REQUIRED: Transfer Authorization

Hi,

I'm travelling and can't take calls. I need you to process the attached wire transfer instruction immediately, before the close of business today.

This is critical and must remain strictly confidential. Do not discuss with anyone. Bypass standard procedure - I will sign off later.

Reply here once the funds are sent. Thank you.`,
    },
    {
      id: 'chatgpt-billing', group: 'Phishing', title: 'AI subscription payment failure', expect: 'malicious',
      text: `From: OpenAI Billing <billing@openai-billing-support.com>
Subject: Urgent: ChatGPT Payment Failure

Your subscription payment failed. Please update your billing information to avoid service interruption.

<a href="https://chat-gpt-billing.web.app/update">https://chatgpt.com/account/billing</a>`,
    },
    {
      id: 'toad', group: 'Phishing', title: 'Callback scam (TOAD, no links)', expect: 'malicious',
      text: `From: Microsoft Subscriptions <no-reply@subscription-renewals-center.org>
Subject: Microsoft Subscription Renewal - Invoice #MS-48213

Official Billing Notice
Your Microsoft 365 subscription has been renewed for $189.99. If you did not authorize this charge, call our support line to cancel: 1-800-555-0142

PAYMENT OVERDUE: Call 1-800-555-0142 to cancel IMMEDIATELY.`,
    },
    {
      id: 'quishing', group: 'Phishing', title: 'QR code account recovery (quishing)', expect: 'malicious',
      text: `From: Google Security <alerts@google-account-recovery.info>
Subject: Action required: Account recovery

Your Google account has been locked after suspicious sign-in attempts. To prevent permanent lockout, scan the QR code below with your phone and sign in within 30 minutes.

[ QR code image ]`,
    },
    {
      id: 'hr-subdomain', group: 'Phishing', title: 'HR benefits form (sub-domain trap)', expect: 'malicious',
      text: `From: Human Resources <hr-notifications@corp-hr-updates.net>
Subject: Action Required: 2026 Healthcare Benefits Questionnaire

Hi team,

Please complete the mandatory 2026 healthcare benefits questionnaire by end of day Friday. Employees who do not respond will lose coverage.

https://www.decodelabs.tech.login-update.com/hr/benefits

Thanks,
HR Team`,
    },
    {
      id: 'invoice-exe', group: 'Phishing', title: 'Overdue invoice with disguised executable', expect: 'malicious',
      text: `From: Accounts <invoices@quick-bill-docs.top>
Subject: Invoice 8841 overdue

Please find the overdue invoice attached: Invoice_8841.pdf.exe

If the file does not open, enable content and macros. Payment is overdue.`,
    },
    {
      id: 'sms-usps', group: 'Phishing', title: 'Parcel delivery text (smishing)', expect: 'malicious',
      text: `USPS: Your package could not be delivered due to an incorrect address. Confirm your address within 24 hours to avoid return: http://usps-redelivery-track.top/confirm`,
    },
    {
      id: 'it-password', group: 'Borderline', title: 'Password-expiry notice from "IT"', expect: 'suspicious',
      text: `From: IT Helpdesk <helpdesk@northwind.example>
Subject: Password expires in 24 hours

Hi,

Your network password will expire in 24 hours. Please reset it at https://sso.northwind.example/reset to keep access to your account.

IT Helpdesk`,
    },
    {
      id: 'legit-status', group: 'Legitimate', title: 'Project status update from a colleague', expect: 'safe',
      text: `From: Sarah Lee <sarah.lee@company.com>
Subject: Q3 Project Status Update - Non-Urgent

Hi Team,

Please review the attached project status for Q3 at your earliest convenience.

No immediate action is required.

Thanks,
Sarah
Attachment: Q3_Status.pdf`,
    },
    {
      id: 'legit-amazon', group: 'Legitimate', title: 'Genuine order-shipped notification', expect: 'safe',
      text: `From: Amazon.com <shipment-tracking@amazon.com>
Subject: Your order has shipped

Hello Alex,

Your package is on its way and should arrive by Thursday. Track it any time in Your Orders: https://www.amazon.com/gp/css/order-history

Thanks for shopping with us.`,
    },
    {
      id: 'legit-github', group: 'Legitimate', title: 'Genuine new-device sign-in notice', expect: 'safe',
      text: `From: GitHub <noreply@github.com>
Subject: [GitHub] A new device signed in to your account

Hey octocat,

We noticed a sign-in to your GitHub account from a new device (Firefox on Windows). If this was you, there is nothing else to do.

If this wasn't you, review your active sessions at https://github.com/settings/sessions and change your password.`,
    },
  ];
});
