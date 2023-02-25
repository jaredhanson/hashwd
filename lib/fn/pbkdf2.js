var pbkdf2 = require('@phc/pbkdf2');

var defer = typeof setImmediate === 'function'
  ? setImmediate
  : function(fn){ process.nextTick(fn.bind.apply(fn, arguments)); };

// NOTE: Might not have "i" parameter
// https://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html#passlib.hash.pbkdf2_sha512

// NOTE: prefer output in this format over passlib format because it is PHC compliant


exports = module.exports = function(digest) {
  return {
    name: 'pbkdf2-' + digest,
    
    hash: function(password, options, cb) {
      if (typeof options == 'function') {
        cb = options;
        options = undefined;
      }
      options = options || {};
  
      var salt = options.salt;
      //var iterations = options.iterations || 310000;
      //var keylen = options.keylen || 32;
      //var digest = options.digest || 'sha256';
  
      var opts = {
        iterations: options.iterations || 310000,
        digest: digest
      };
  
      var p = pbkdf2.hash(password, opts);
      p.then(function(str) {
        return defer(cb, null, str)
      }, function(err) {
        return defer(cb, err);
      });
    },
    
    verify: function(password, hash, cb) {
      if (typeof options == 'function') {
        cb = options;
        options = undefined;
      }
  
      var p = pbkdf2.verify(hash, password);
      p.then(function(ok) {
        return defer(cb, null, ok);
      }, function(err) {
        return defer(cb, err);
      });
    },
    
    needsUpgrade: function(hash, options) {
  
    }
  };
};
