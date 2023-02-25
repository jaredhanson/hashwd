var expect = require('chai').expect;
var pbkdf2_sha256 = require('../../lib/fn/pbkdf2-sha256');


describe('$pbkdf2-sha256$', function() {

  it('should hash and verify password', function(done) {
    pbkdf2_sha256.hash('keyboard cat', function(err, hashstr) {
      if (err) { return done(err); }
    
      expect(hashstr).to.be.a('string');
      expect(hashstr).to.startWith('$pbkdf2-sha256$');
      
      pbkdf2_sha256.verify('keyboard cat', hashstr, function(err, ok) {
        if (err) { return done(err); }
      
        expect(ok).to.be.true;
        done();
      });
    });
  }); // should hash and verify password

}); // $pbkdf2-sha256$
