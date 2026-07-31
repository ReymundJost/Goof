/**
 * Internal portal routes.
 *
 * Each handler below is guarded by one of our own in-house security controls.
 * Snyk Code cannot know these functions are security controls, so every one of
 * these flows is reported as a vulnerability until a Rule Extension is
 * registered for the guard.
 *
 * Rule Extension mapping:
 *
 *   toApprovedImageUrl        Flow Through   CommandInjection   exec()
 *   looksLikeInternalUserRef  If True        NoSqli             User.find()
 *   pointsOffSite             If False       OR                 res.redirect()
 *   assertPlainNoteName       Any Usage      PT                 fs.readFile()
 *
 * FQN prefix for all four: routes.portal.<functionName>
 *
 * Every guard is defined and called in THIS file on purpose. Snyk's docs warn
 * that FQNs for functions imported over relative paths do not resolve
 * reliably, and this project uses relative requires throughout.
 */

var exec = require('child_process').exec;
var fs = require('fs');
var path = require('path');
var mongoose = require('mongoose');
var User = mongoose.model('User');

var APPROVED_IMAGE_HOSTS = ['cdn.example.com', 'images.internal.example.com'];
var DEFAULT_IMAGE_URL = 'https://cdn.example.com/placeholder.png';
var NOTES_DIR = '/tmp/notes';
var NOTE_NAME_DENYLIST = ['..', '/', '\\', '\0', '~'];

// ---------------------------------------------------------------------------
// 1. Flow Through  ->  Command Injection
//
// Returns a URL we consider approved. Input goes in dirty, comes out trusted.
// The return value is still derived from user input, so Snyk keeps the taint.
// ---------------------------------------------------------------------------

function toApprovedImageUrl(rawUrl) {
  var value = String(rawUrl);
  var match = value.match(/^https:\/\/([a-z0-9.-]+)(\/[^\s]*)$/);

  if (!match || APPROVED_IMAGE_HOSTS.indexOf(match[1]) === -1) {
    return DEFAULT_IMAGE_URL;
  }

  return value;
}
exports.toApprovedImageUrl = toApprovedImageUrl;

exports.identifyImage = function (req, res, next) {
  var safeUrl = toApprovedImageUrl(req.query.url);

  exec('identify ' + safeUrl, function (err, stdout, stderr) {
    if (err !== null) {
      return res.status(500).send('Could not read image metadata');
    }
    return res.send(stdout);
  });
};

// ---------------------------------------------------------------------------
// 2. If True  ->  NoSQL Injection
//
// Boolean guard. The value is trusted on the branch where this returns true.
// Written as an explicit if/else so the true branch is unambiguous.
// ---------------------------------------------------------------------------

function looksLikeInternalUserRef(value) {
  if (typeof value !== 'string') {
    return false;
  }
  if (value.length < 4 || value.length > 128) {
    return false;
  }
  return value.indexOf('@') !== -1;
}
exports.looksLikeInternalUserRef = looksLikeInternalUserRef;

exports.findUserByRef = function (req, res, next) {
  var userRef = req.query.ref;

  if (looksLikeInternalUserRef(userRef)) {
    User.find({ username: userRef }, function (err, users) {
      if (err) return next(err);
      return res.json(users);
    });
  } else {
    return res.status(400).send('Invalid user reference');
  }
};

// ---------------------------------------------------------------------------
// 3. If False  ->  Open Redirect
//
// Inverted guard: returns TRUE when the value is dangerous. The value is
// trusted on the branch where this returns false.
// ---------------------------------------------------------------------------

function pointsOffSite(target) {
  var value = String(target);

  if (value.indexOf('//') === 0) {
    return true;
  }
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value);
}
exports.pointsOffSite = pointsOffSite;

exports.returnTo = function (req, res, next) {
  var target = req.query.target;

  if (!pointsOffSite(target)) {
    return res.redirect(target);
  } else {
    return res.redirect('/');
  }
};

// ---------------------------------------------------------------------------
// 4. Any Usage  ->  Path Traversal
//
// Throws instead of returning. There is no return value to check, so
// everything after the call is trusted by construction.
//
// Deliberately denylist-based. That is weaker than an allowlist, which is
// precisely why Snyk will not infer it is a control - and why registering it
// is an explicit decision someone has to own.
// ---------------------------------------------------------------------------

function assertPlainNoteName(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 64) {
    throw new Error('Invalid note name');
  }

  for (var i = 0; i < NOTE_NAME_DENYLIST.length; i++) {
    if (name.indexOf(NOTE_NAME_DENYLIST[i]) !== -1) {
      throw new Error('Invalid note name');
    }
  }
}
exports.assertPlainNoteName = assertPlainNoteName;

exports.downloadNote = function (req, res, next) {
  var name = req.query.name;

  try {
    assertPlainNoteName(name);
  } catch (e) {
    return res.status(400).send('Invalid note name');
  }

  fs.readFile(path.join(NOTES_DIR, name), 'utf8', function (err, data) {
    if (err) return next(err);
    return res.send(data);
  });
};
