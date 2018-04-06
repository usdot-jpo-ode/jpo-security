package gov.usdot.cv.security.cert;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;

public class SecurePrivateKey extends SecureAbstractKey {

   public SecurePrivateKey() {
      super();
   }

   public SecurePrivateKey(KeyStore keyStore, Key key) {
      super(keyStore, key);

      if (!(key instanceof PrivateKey)) {
         throw new IllegalArgumentException("Provided key is not an instance of java.security.PrivateKey!");
      }
   }

}
