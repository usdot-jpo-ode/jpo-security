package gov.usdot.cv.security.msg;

import java.io.IOException;
import java.text.ParseException;

import gov.usdot.cv.security.cert.CertificateWrapper;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.clock.ClockHelperTest;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

public class TestCertificateStore {
	
    static final private boolean isDebugOutput = false;
    private static final Logger log = Logger.getLogger(TestCertificateStore.class);
    
    private static final String certsValidDate = "Thu May 11 02:00:00 EDT 2017";
    
    private static final String PcaCert = "<hex of the bytes from trustedcerts/pca file>";

    private static final String SigningPrivateKey = "<hex of the bytes from sign.prv>";
    
    private static final String SelfCert  = "<hex of the bytes from downloadFiles/559f72e456956030.cert>";
    private static final String SelfCertPrivateKeyReconstructionValue = "<hex of the bytes from downloadFiles/559f72e456956030.s>";
    
    private static final String ClientCert  = "<hex of the bytes from downloadFiles/fdd0a6aafb493c6d.cert>";
    private static final String ClientCertPrivateKeyReconstructionValue = "<hex of the bytes from downloadFiles/fdd0a6aafb493c6d.s>";
    
	public static void load() throws ParseException, DecoderException, CertificateException, IOException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
		CryptoProvider.initialize();
        UnitTestHelper.initLog4j(isDebugOutput);
        
		ClockHelperTest.setNow(certsValidDate);
		
		CryptoProvider cryptoProvider = new CryptoProvider();
		
		String[] names = { "PCA", "Self", "Client" };
		for( String name : names )
			if ( !load(cryptoProvider, name) )
				throw new CertificateException("Couldn't load certificate named " + name);
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name) throws DecoderException, CertificateException, IOException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
		if ( name == null )
			return false;
		if ( name.equals("PCA") )
			return load(cryptoProvider, "PCA", PcaCert);
		if ( name.equals("Self") )
			return load(cryptoProvider, "Self", SelfCert, SelfCertPrivateKeyReconstructionValue, SigningPrivateKey);
		if ( name.equals("Client") )
			return load(cryptoProvider, "Client", ClientCert, ClientCertPrivateKeyReconstructionValue, SigningPrivateKey);
		return false;
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name, String hexCert) throws DecoderException, CertificateException, IOException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
    	return load(cryptoProvider, name, hexCert, null, null);
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name, String hexCert,
								String hexPrivateKeyReconstructionValue, String hexSigningPrivateKey)
										throws CertificateException, IOException, DecoderException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
    	byte[] certBytes = Hex.decodeHex(hexCert.toCharArray());
    	CertificateWrapper cert;
    	if ( hexPrivateKeyReconstructionValue == null && hexSigningPrivateKey == null ) {
    		cert = CertificateWrapper.fromBytes(cryptoProvider, certBytes);
    	} else {
	    	byte[] privateKeyReconstructionValueBytes = Hex.decodeHex(hexPrivateKeyReconstructionValue.toCharArray());
	    	byte[] signingPrivateKeyBytes = Hex.decodeHex(hexSigningPrivateKey.toCharArray());
	    	cert = CertificateWrapper.fromBytes(cryptoProvider, certBytes, privateKeyReconstructionValueBytes, signingPrivateKeyBytes);
    	}
    	if ( cert != null ) {
    		boolean isValid = cert.isValid();
    		log.debug("Certificate is valid: " + isValid);
    		if ( isValid )
    			CertificateManager.put(name, cert);
    		return isValid;
    	}
    	return false;
	}
}
