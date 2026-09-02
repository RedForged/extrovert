'use strict';

const { getUserById } = require('./db');
const { getSignedInAccounts } = require('./accounts');

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  const user = getUserById(req.session.userId);
  if (user && user.banned) {
    // Banned users behave as signed-out on every web route.
    res.locals.currentUser = null;
    return next();
  }
  // getSignedInAccounts first: it drops deleted accounts from the device list
  // and fixes userId if the active account is gone.
  res.locals.signedInAccounts = getSignedInAccounts(req);
  res.locals.currentUser = user;
  next();
}

function optionalAuth(req, res, next) {
  if (req.session.userId) {
    const user = getUserById(req.session.userId);
    if (user && user.banned) {
      res.locals.currentUser = null;
    } else {
      res.locals.signedInAccounts = getSignedInAccounts(req);
      res.locals.currentUser = user;
    }
  }
  next();
}

module.exports = { requireAuth, optionalAuth };
