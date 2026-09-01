'use strict';

// Responsible disclosure: public policy page, RFC 9116 security.txt, and the
// private report inbox. Reports are stored in security_reports and are visible
// ONLY to admins — nothing here is ever rendered on public pages.

const express = require('express');
const { createSecurityReport } = require('../db');
const { ISSUER } = require('../oidc');

const router = express.Router();
// Security contact email. Optional: when unset, the /security page and
// security.txt advertise no email at all (the in-app form and the
// <issuer>/security URL remain the contact) instead of a misleading placeholder.
const CONTACT_EMAIL = (process.env.SECURITY_CONTACT_EMAIL || '').trim() || null;

// The mailto form for security.txt; null when no contact email is configured.
function contactMailto() {
  return CONTACT_EMAIL ? (/^mailto:/i.test(CONTACT_EMAIL) ? CONTACT_EMAIL : `mailto:${CONTACT_EMAIL}`) : null;
}
router.get('/security', (req, res) => {
  res.render('security', {
    sent: req.query.sent === '1',
    error: req.query.error,
    contactEmail: CONTACT_EMAIL,
    csrfToken: req.session.csrfToken,
  });
});

// Submit a private security report. Anonymous-friendly; CSRF-protected by the
// global middleware and rate-limited by the global action limiter.
router.post('/security/report', (req, res) => {
  const summary = String(req.body.summary || '').trim().slice(0, 200);
  const details = String(req.body.details || '').trim().slice(0, 5000);
  const reporterName = String(req.body.reporter_name || '').trim().slice(0, 100);
  const reporterContact = String(req.body.reporter_contact || '').trim().slice(0, 200);

  if (!summary || !details) {
    return res.redirect('/security?error=missing');
  }

  try {
    createSecurityReport({ reporterName, reporterContact, summary, details });
    const db = require('../db');
    db.auditLog('security_report', null, `Security report: ${summary}`);
  } catch (e) {
    console.error('security report storage failed:', e.message);
    return res.redirect('/security?error=storage');
  }
  res.redirect('/security?sent=1');
});

// RFC 9116 security.txt (machine-readable, private contact).
router.get('/security.txt', (req, res) => {
  res.redirect(301, '/.well-known/security.txt');
});

module.exports = router;
module.exports.contactMailto = contactMailto;
module.exports.CONTACT_EMAIL = CONTACT_EMAIL;
