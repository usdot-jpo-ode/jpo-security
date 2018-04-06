package gov.usdot.cv.security.cert;

import java.security.Key;
import java.security.KeyStore;

public abstract class SecureAbstractKey implements SecureKey {
   private KeyStore keyStore;
   private Key key;

   public SecureAbstractKey() {
      super();
   }

   public SecureAbstractKey(KeyStore keyStore, Key key) {
      super();
      this.keyStore = keyStore;
      this.key = key;
   }

   public KeyStore getKeyStore() {
      return keyStore;
   }

   public void setKeyStore(KeyStore keyStore) {
      this.keyStore = keyStore;
   }

   public Key getKey() {
      return key;
   }

   public void setKey(Key key) {
      this.key = key;
   }

}
