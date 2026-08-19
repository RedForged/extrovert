'use strict';

const express = require('express');
const { getAllUsers, getUserById, removeReferralBadge, banUser, unbanUser, deleteUser, getAllRooms, deleteRoom, getPendingReports, getReport, resolveReport, dismissReport, promoteUser, getAnnouncement, setAnnouncement, clearAnnouncement, getSecurityReports, markSecurityReportHandled, getSetting } = require('../db');

const router = express.Router();

function requireAdmin(req, res, next) {
  const user = res.locals.currentUser;
  if (!user || !user.is_admin) return res.status(403).send('Admins only.');
  next();
}

router.get('/', requireAdmin, (req, res) => {
  const users = getAllUsers();
  const rooms = getAllRooms();
  const reports = getPendingReports();
  res.render('admin', { users, rooms, reports });
});

router.post('/remove-referral/:id', requireAdmin, (req, res) => {
  const target = getUserById(Number(req.params.id));
  if (!target) return res.status(404).send('User not found');
  removeReferralBadge(target.id);
  res.redirect('/admin');
});

router.post('/ban/:id', requireAdmin, (req, res) => {
  const target = getUserById(Number(req.params.id));
  if (!target) return res.status(404).send('User not found');
  if (target.is_admin) return res.status(403).send('Cannot ban another admin.');
  banUser(target.id);
  res.redirect('/admin');
});

router.post('/unban/:id', requireAdmin, (req, res) => {
  const target = getUserById(Number(req.params.id));
  if (!target) return res.status(404).send('User not found');
  unbanUser(target.id);
  res.redirect('/admin');
});

router.post('/delete/:id', requireAdmin, (req, res) => {
  const target = getUserById(Number(req.params.id));
  if (!target) return res.status(404).send('User not found');
  if (target.is_admin) return res.status(403).send('Cannot delete another admin.');
  deleteUser(target.id);
  res.redirect('/admin');
});

router.post('/make-admin/:id', requireAdmin, (req, res) => {
  const target = getUserById(Number(req.params.id));
  if (!target) return res.status(404).send('User not found');
  if (target.is_admin) return res.status(400).send('Already an admin');
  if (target.banned) return res.status(400).send('Cannot promote banned user');
  promoteUser(target.id);
  res.redirect('/admin');
});

// Admin: delete any room
router.post('/rooms/:id/delete', requireAdmin, (req, res) => {
  const room = getAllRooms().find(r => r.id === Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  deleteRoom(room.id);
  res.redirect('/admin#rooms');
});

// Admin: reports
router.get('/reports', requireAdmin, (req, res) => {
  const reports = getPendingReports();
  res.render('admin-reports', { reports });
});

router.post('/reports/:id/ban', requireAdmin, (req, res) => {
  const report = getReport(Number(req.params.id));
  if (!report) return res.status(404).send('Report not found');
  if (report.status !== 'pending') return res.status(400).send('Report already resolved');
  const target = getUserById(report.reported_user_id);
  if (!target) return res.status(404).send('User not found');
  if (target.is_admin) return res.status(403).send('Cannot ban another admin');
  banUser(target.id);
  resolveReport(report.id);
  res.redirect('/admin/reports');
});

router.post('/reports/:id/dismiss', requireAdmin, (req, res) => {
  const report = getReport(Number(req.params.id));
  if (!report) return res.status(404).send('Report not found');
  if (report.status !== 'pending') return res.status(400).send('Report already resolved');
  dismissReport(report.id);
  res.redirect('/admin/reports');
});

// Private security reports (responsible-disclosure inbox). Admin-only.
router.get('/security-reports', requireAdmin, (req, res) => {
  const reports = getSecurityReports();
  res.render('admin-security-reports', { reports });
});

router.post('/security-reports/:id/handle', requireAdmin, (req, res) => {
  const ok = markSecurityReportHandled(Number(req.params.id), res.locals.currentUser.id);
  if (!ok) return res.status(404).send('Report not found or already handled.');
  res.redirect('/admin/security-reports');
});

// Announcement CRUD — only one server-wide announcement exists at a time.
router.get('/announcement', requireAdmin, (req, res) => {
  res.render('admin-announcement', {
    announcement: getAnnouncement(),
    error: null,
  });
});

router.post('/announcement', requireAdmin, (req, res) => {
  const user = res.locals.currentUser;
  const body = (req.body && req.body.body) || '';
  if (!String(body).trim()) {
    return res.render('admin-announcement', {
      announcement: getAnnouncement(),
      error: 'Announcement cannot be empty.',
    });
  }
  setAnnouncement(body, user.id);
  res.redirect('/admin');
});

router.post('/announcement/clear', requireAdmin, (req, res) => {
  clearAnnouncement();
  res.redirect('/admin');
});

// ---------- Mail / email-verification admin panel ----------
const mailer = require('../mailer');
const { getMailSettings, setMailSettings, getEmailPolicy, setEmailPolicy } = require('../db');

// The DKIM signer domain shown in the panel (DKIM domain or the From domain).
function dkimDomainOf(eff) {
  return eff.dkim.domain || (eff.from && eff.from.includes('@') ? eff.from.split('@')[1] : '');
}

function renderMailPanel(res, { error = null, saved = false } = {}) {
  const effective = mailer.reloadConfig();
  res.render('admin-mail', {
    stored: getMailSettings(),
    // The raw DB value (null = inherit from env/default) — used so the panel
    // can show "Inherit" as selected; `policy` below is the effective value.
    storedPolicy: getSetting('email_verification_policy'),
    records: mailer.dnsRecords(),
    policy: getEmailPolicy(),
    effective,
    dkimDomain: dkimDomainOf(effective),
    error,
    saved,
  });
}

router.get('/mail', requireAdmin, (req, res) => {
  renderMailPanel(res);
});

router.post('/mail', requireAdmin, (req, res) => {
  const b = req.body || {};
  try {
    // Policy + mail settings. Empty inputs unset the DB value, returning
    // control to the environment variable (Portainer) / built-in default.
    setEmailPolicy(String(b.policy || '').trim());
    setMailSettings({
      mode: String(b.mode || '').trim(),
      relay: String(b.relay || '').trim(),
      from: String(b.from || '').trim(),
      from_name: String(b.from_name || '').trim(),
      bounce_from: String(b.bounce_from || '').trim(),
      dkim_enabled: String(b.dkim_enabled || '').trim(),
      dkim_domain: String(b.dkim_domain || '').trim(),
      dkim_selector: String(b.dkim_selector || '').trim(),
      starttls: String(b.starttls || '').trim(),
      outbox_fallback: String(b.outbox_fallback || '').trim(),
      timeout_ms: String(b.timeout_ms || '').trim(),
      max_attempts: String(b.max_attempts || '').trim(),
    });
    // DKIM private key: only overwrite when the admin pastes a new one; an
    // empty field leaves the existing key (DB or env) untouched.
    const newKey = String(b.dkim_private_key || '').trim();
    if (newKey) setMailSettings({ dkim_private_key: newKey });

    renderMailPanel(res, { saved: true });
  } catch (err) {
    console.error('admin/mail: save failed', err);
    renderMailPanel(res, { error: 'Failed to save: ' + (err.message || err) });
  }
});

module.exports = router;
