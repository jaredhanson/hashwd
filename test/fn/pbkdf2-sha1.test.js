var expect = require('chai').expect;
var pbkdf2_sha1 = require('../../lib/fn/pbkdf2-sha1');


describe('$pbkdf2-sha1$', function() {

  it('should hash and verify password', function(done) {
    pbkdf2_sha1.hash('keyboard cat', function(err, hashstr) {
      if (err) { return done(err); }
    
      expect(hashstr).to.be.a('string');
      expect(hashstr).to.startWith('$pbkdf2-sha1$');
      
      pbkdf2_sha1.verify('keyboard cat', hashstr, function(err, ok) {
        if (err) { return done(err); }
      
        expect(ok).to.be.true;
        done();
      });
    });
  }); // should hash and verify password

}); // $pbkdf2-sha1$
