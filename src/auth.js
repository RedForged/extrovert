'use strict';

const { getUserById } = require('./db');
const { getSignedInAccounts } = require('./accounts');

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  // getSignedInAccounts first: it drops deleted accounts from the device list
  // and fixes userId if the active account is gone.
  res.locals.signedInAccounts = getSignedInAccounts(req);
  res.locals.currentUser = getUserById(req.session.userId);
  next();
}

function optionalAuth(req, res, next) {
  if (req.session.userId) {
    res.locals.signedInAccounts = getSignedInAccounts(req);
    res.locals.currentUser = getUserById(req.session.userId);
  }
  next();
}

module.exports = { requireAuth, optionalAuth };
