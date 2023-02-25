var phc = require('@phc/format');
var pbkdf2sha512 = require('./fn/pbkdf2-sha512');

function Crypter() {
  this._fns = {};
  this.init();
}

Crypter.prototype.init = function() {
  this.use(pbkdf2sha512);
  
  this.current('pbkdf2-sha512');
};

Crypter.prototype.use = function(name, fn) {
  if (!fn) {
    fn = name;
    name = fn.name;
  }
  if (!name) { throw new Error('Password hashing functions must have a symbolic name'); }
  
  this._fns[name] = fn;
  return this;
};

Crypter.prototype.current = function(name, options) {
  this._currName = name;
};

Crypter.prototype.hash = function(password, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  var fn = this._fns[this._currName];
  if (!fn) { throw new Error('Unsupported password hashing function "' + this._currName + '"'); }
  fn.hash(password, options, cb);
};

Crypter.prototype.verify = function(password, hash, cb) {
  var obj = phc.deserialize(hash);
  var fn = this._fns[obj.id];
  if (!fn) { throw new Error('Unsupported password hashing function "' + obj.id + '"'); }
  fn.verify(password, hash, cb);
};

module.exports = Crypter;
