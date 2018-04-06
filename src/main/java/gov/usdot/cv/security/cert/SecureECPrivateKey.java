package gov.usdot.cv.security.cert;

import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.ECPrivateKey;

public class SecureECPrivateKey extends SecurePrivateKey {

   public SecureECPrivateKey() {
      super();
   }

   public SecureECPrivateKey(KeyStore keyStore, Key key) {
      super(keyStore, key);

      if (!(key instanceof ECPrivateKey)) {
         throw new IllegalArgumentException("Provided key is not an instance of java.security.interfaces.ECPrivateKey!");
      }
   }

}
