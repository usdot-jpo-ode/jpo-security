package gov.usdot.cv.security.util;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.util.Enumeration;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

import gov.usdot.cv.security.cert.SecureECPrivateKey;
import gov.usdot.cv.security.crypto.ECDSAProvider;

/**
 * Unit test logging initializer
 */
public class UnitTestHelper {
	
	/**
	 * Sets logging level from boolean
	 * @param isDebugOutput if true, logging level is set to DEBUG, otherwise it's set to INFO
	 */
	public static void initLog4j(boolean isDebugOutput) {
		initLog4j(isDebugOutput ? Level.DEBUG : Level.INFO);
	}
	
	/**
	 * Set logging level to the level specified
	 * @param level new logging level
	 */
	public static void initLog4j(Level level) {
	    Logger rootLogger = Logger.getRootLogger();
	    @SuppressWarnings("rawtypes")
		Enumeration appenders = rootLogger.getAllAppenders();
	    if ( appenders == null || !appenders.hasMoreElements() ) {
		    rootLogger.setLevel(level);
		    rootLogger.addAppender(new ConsoleAppender(new PatternLayout("%-6r [%p] %c - %m%n")));
	    }
	}
	
   public static KeyStore inMemoryKeyStore() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
      KeyStore keyStore = KeyStore.getInstance("BC");
      keyStore.load(null, null);
      return keyStore;
   }
   
   public static SecureECPrivateKey createUnsecurePrivateKey(KeyStore keystore) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA");
      ECGenParameterSpec ecSpec = new ECGenParameterSpec(ECDSAProvider.KEYPAIR_GENERATION_ALGORTHM_SPECS);
      kpg.initialize(ecSpec, new SecureRandom());
      KeyPair keypair = kpg.generateKeyPair();
      return new SecureECPrivateKey(keystore, keypair.getPrivate());
   }
   
}
