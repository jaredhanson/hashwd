var expect = require('chai').expect;
var Crypter = require('../lib/crypter');


describe('Crypter', function() {
  
  describe('#hash', function() {
  
    it('should hash password with pbkdf2-sha512', function(done) {
      var crypter = new Crypter();
      
      crypter.hash('keyboard cat', function(err, hashstr) {
        if (err) { return done(err); }
        
        expect(hashstr).to.be.a('string');
        expect(hashstr).to.startWith('$pbkdf2-sha512$');
        done();
      });
    }); // should hash password with pbkdf2-sha512
    
  }); // #hash
  
  describe('#verify', function() {
  
    it('should verify password against pbkdf2-sha512 hash string', function(done) {
      var crypter = new Crypter();
      
      crypter.verify('keyboard cat', '$pbkdf2-sha512$i=310000$L2waYGbOdZicDUSdmCKrjw$A23miLeRQLYzgPboVT0HoDkR8KUgCUjPu9cmnQk58SODiMct5bfGCySfNWs0QI+l6f8//+yq1MKCB3T6X+coDA', function(err, ok) {
        if (err) { return done(err); }
        
        expect(ok).to.be.a('boolean');
        expect(ok).to.be.true;
        done();
      });
    }); // should verify password against pbkdf2-sha512 hash string
    
  }); // #verify
  
}); // Crypter
