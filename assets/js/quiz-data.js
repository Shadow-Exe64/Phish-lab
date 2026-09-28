/*!
 * "Spot the phish" training scenarios. Fictional company: Northwind Ltd (northwind.example).
 * `flags` lists what a careful reader should notice; empty for legitimate mail.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PhishQuiz = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return [
    {
      id: 'q-paypal', phish: true, channel: 'Email', name: 'PayPal Service', addr: 'service@paypa1-support.com',
      subject: 'Your account has been limited', body: 'Dear Customer,\n\nWe noticed unusual activity and have limited your account. Confirm your identity within 24 hours to restore access.',
      links: [{ text: 'Restore my account', href: 'https://paypa1-support.com/verify/login' }],
      flags: ['Sender domain "paypa1" uses the digit 1 instead of the letter l', 'Generic greeting: "Dear Customer"', 'Urgency: a 24-hour deadline', 'Asks you to confirm your identity through a link'],
      why: 'Real PayPal mail comes from paypal.com. One swapped character is all it takes to look official.',
    },
    {
      id: 'q-calendar', phish: false, channel: 'Email', name: 'Priya Nair', addr: 'priya.nair@northwind.example',
      subject: 'Team sync moved to 10:00', body: 'Hi all,\n\nI have moved tomorrow\'s team sync to 10:00. Same video link as usual, agenda is in the shared doc.\n\nPriya',
      links: [{ text: 'Join the meeting', href: 'https://meet.google.com/abc-defg-hij' }],
      flags: [], why: 'Known colleague, internal address, no pressure, no request for information, and the link goes to a genuine Google Meet address.',
    },
    {
      id: 'q-giftcards', phish: true, channel: 'Email', name: 'Daniel Ortiz (CEO)', addr: 'daniel.ortiz.ceo@gmail.com',
      subject: 'Quick favour - keep this between us', body: 'Are you at your desk? I\'m in a meeting and can\'t talk. I need 5 gift cards for a client today. Buy them and send me the codes, I\'ll reimburse you. Please don\'t mention this to anyone yet.',
      links: [],
      flags: ['Executive name but a free Gmail address', 'Secrecy: "keep this between us"', 'Asks for gift-card codes, a classic payment scam', 'Urgency and "can\'t talk" to stop you verifying by phone'],
      why: 'Executives do not ask staff to buy gift cards secretly. Verify by calling a number from the company directory.',
    },
    {
      id: 'q-mailbox', phish: true, channel: 'Email', name: 'Microsoft 365', addr: 'no-reply@mailbox-notice.net',
      subject: 'Mailbox storage 98% full', body: 'Your mailbox is almost full and incoming mail will be rejected. Increase your storage now to avoid losing messages.',
      links: [{ text: 'Increase storage', href: 'https://outlook.office365.com.mailbox-restore.net/login' }],
      flags: ['Sender domain is mailbox-notice.net, not microsoft.com', 'Link starts with outlook.office365.com but the real domain is mailbox-restore.net (read right to left)', 'Threat of losing mail creates pressure'],
      why: 'The trusted-looking part is a fake sub-domain. Only the last two labels before the first slash decide who owns the site.',
    },
    {
      id: 'q-amazon', phish: false, channel: 'Email', name: 'Amazon.com', addr: 'shipment-tracking@amazon.com',
      subject: 'Your package was delivered', body: 'Hello Sam,\n\nYour package was delivered today at 2:14 PM and left at your front door. You can review your order any time.',
      links: [{ text: 'View your order', href: 'https://www.amazon.com/gp/css/order-history' }],
      flags: [], why: 'Address and link both belong to amazon.com, it is personalised, and nothing asks for a password or payment.',
    },
    {
      id: 'q-sms', phish: true, channel: 'SMS', name: '+44 7700 900123', addr: '+44 7700 900123',
      subject: 'Delivery notice', body: 'Your parcel is held at the depot. A 1.99 redelivery fee is required. Pay within 12 hours or it will be returned.',
      links: [{ text: 'https://bit.ly/3xRedeliver', href: 'https://bit.ly/3xRedeliver' }],
      flags: ['Shortened link hides the destination', 'Small fee plus a 12-hour deadline', 'No order number or name: it is a mass message'],
      why: 'Smishing often asks for a tiny fee so that the real goal, your card details, feels harmless.',
    },
    {
      id: 'q-toad', phish: true, channel: 'Email', name: 'Norton Billing', addr: 'billing@secure-renewal-desk.org',
      subject: 'Your subscription was renewed: $349.99', body: 'Thank you for renewing your antivirus subscription. $349.99 has been charged to your card. If you did not authorise this, call 1-800-555-0177 immediately to cancel and get a refund.',
      links: [],
      flags: ['No link, only a phone number: callback phishing (TOAD)', 'Large unexpected charge to alarm you', 'Sender domain does not match the brand', '"Immediately" adds pressure'],
      why: 'The "agent" you call will ask you to install remote-access software. Emails with only a number bypass link scanners.',
    },
    {
      id: 'q-hr', phish: false, channel: 'Email', name: 'Northwind HR', addr: 'hr@northwind.example',
      subject: 'Public holiday schedule 2026', body: 'Hi everyone,\n\nThe office holiday calendar for 2026 is attached for your information. No action is needed.\n\nHR Team',
      links: [], flags: [], why: 'Internal domain, purely informational, no link, no urgency and no request.',
    },
    {
      id: 'q-docusign', phish: true, channel: 'Email', name: 'DocuSign via Finance', addr: 'dse@docusign-secure-docs.com',
      subject: 'Please review and sign: Vendor_Agreement.html', body: 'A document is waiting for your signature. Open the attached file in your browser. If the page appears blank, click "Enable content" to display it.',
      links: [],
      flags: ['Attachment is an .html file (HTML smuggling)', '"Enable content" instruction', 'Domain adds "secure-docs" to the DocuSign name (combosquatting)'],
      why: 'An HTML attachment can draw a fake login page locally, so URL filters never see it.',
    },
    {
      id: 'q-otp', phish: true, channel: 'Email', name: 'IT Security', addr: 'it.security@northwind-helpdesk.com',
      subject: 'We are blocking a sign-in to your account', body: 'We have seen an unauthorised sign-in attempt. To stop it, reply with the 6-digit verification code we just sent to your phone.',
      links: [],
      flags: ['Asks you to share a one-time code, which no real IT team does', 'Domain northwind-helpdesk.com is not northwind.example', 'Fear: unauthorised sign-in attempt'],
      why: 'Sharing a code hands the attacker your second factor. Codes are for you alone.',
    },
    {
      id: 'q-github', phish: false, channel: 'Email', name: 'GitHub', addr: 'noreply@github.com',
      subject: '[GitHub] A new device signed in to your account', body: 'Hey octocat,\n\nA sign-in to your account came from a new device. If this was you, there is nothing to do. If not, review your sessions in your account settings.',
      links: [{ text: 'Review sessions', href: 'https://github.com/settings/sessions' }],
      flags: [], why: 'Real domain, no pressure, and it says "if this was you, do nothing". It also does not ask for a password.',
    },
    {
      id: 'q-voicemail', phish: true, channel: 'Email', name: 'Director Ellis', addr: 'j.ellis@northwind-corp.co',
      subject: 'Re: My Voice Message', body: 'Hi, I just left you a voicemail about the urgent request we discussed. Please confirm ASAP so I can proceed.',
      links: [],
      flags: ['Vague "request we discussed" that you never discussed', 'Domain northwind-corp.co is a look-alike of the company domain', 'AI voicemail plus follow-up email: a deepfake pattern', 'Urgency: "confirm ASAP"'],
      why: 'Attackers pair a cloned voice with a short email. Call the person back on a number you already have.',
    },
  ];
});
