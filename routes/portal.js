/**
 * Internal portal routes - Rule Extensions demo.
 *
 * Built to the same recipe as the one sanitizer that already works
 * (validator.isEmail / NoSqli / If True). Two properties make it work:
 *
 *  1. The guard is an npm package function, so the call site is
 *     MODULE-QUALIFIED - `validator.stripLow(...)`, not a bare local call.
 *     Snyk resolves a sanitizer's FQN from how it is referenced at the call
 *     site; the documented supported patterns are explicit class references
 *     and functions imported over absolute module paths. A bare local
 *     function has no module qualifier and does not resolve.
 *
 *  2. The function's normal meaning does NOT match the rule it is being
 *     registered against. Snyk already ships sanitizer knowledge for popular
 *     libraries, so registering something it already treats as a sanitizer for
 *     that rule changes nothing - the finding was gone before you started.
 *     `isEmail` is not a NoSQL control, which is exactly why it had something
 *     left to suppress.
 *
 * Rule Extension mapping:
 *
 *   validator.stripLow   Flow Through   CommandInjection   exec()
 *   validator.contains   If False       OR                 res.redirect()
 *   assert.match         Any Usage      PT                 fs.readFile()
 *
 * Each guard receives a plain variable, and the SAME variable reaches the sink.
 * Never a property read or an expression built inline - Snyk treats a value
 * reconstructed at the sink as a different object from the one the guard saw.
 */

var exec = require('child_process').exec;
var fs = require('fs');
var path = require('path');
var assert = require('assert');
var validator = require('validator');

var NOTES_DIR = '/tmp/notes';
var NOTE_PATH_PATTERN = /^\/tmp\/notes\/[a-zA-Z0-9_-]{1,64}\.txt$/;

// ---------------------------------------------------------------------------
// 1. Flow Through  ->  Command Injection      FQN: validator.stripLow
//
// stripLow() removes control characters and returns a string. Our team's
// convention is to strip them before shelling out. It is not a command
// injection control - it does nothing about ; or | - which is precisely why
// Snyk still reports this flow, and why registering it is a decision someone
// has to justify. Good material for the governance point.
// ---------------------------------------------------------------------------

exports.identifyImage = function (req, res, next) {
  var imageUrl = req.query.url;
  var safeUrl = validator.stripLow(imageUrl);

  exec('identify ' + safeUrl, function (err, stdout, stderr) {
    if (err !== null) {
      return res.status(500).send('Could not read image metadata');
    }
    return res.send(stdout);
  });
};

// ---------------------------------------------------------------------------
// 2. If False  ->  Open Redirect              FQN: validator.contains
//
// Inverted guard: contains(target, ':') returns TRUE when the value carries a
// scheme, i.e. when it is dangerous. The value is trusted on the branch where
// the call returns FALSE - relative paths only.
// ---------------------------------------------------------------------------

exports.returnTo = function (req, res, next) {
  var target = req.query.target;

  if (!validator.contains(target, ':')) {
    return res.redirect(target);
  } else {
    return res.redirect('/');
  }
};

// ---------------------------------------------------------------------------
// 3. Any Usage  ->  Path Traversal            FQN: assert.match
//
// assert.match() throws when the value does not match. There is no return
// value to check, so everything after the call is trusted by construction -
// the Any Usage shape.
//
// Note the guard validates notePath, the SAME variable passed to fs.readFile.
// Building path.join() inline inside the readFile call would hand the sink a
// value the guard never saw.
//
// Requires Node 13+ for assert.match. On older Node use assert.ok with a
// pre-computed boolean - but then the sanitized argument is the boolean, not
// notePath, and the extension will not bind.
// ---------------------------------------------------------------------------

exports.downloadNote = function (req, res, next) {
  var name = req.query.name;
  var notePath = path.join(NOTES_DIR, name);

  try {
    assert.match(notePath, NOTE_PATH_PATTERN);
  } catch (e) {
    return res.status(400).send('Invalid note name');
  }

  fs.readFile(notePath, 'utf8', function (err, data) {
    if (err) return next(err);
    return res.send(data);
  });
};
