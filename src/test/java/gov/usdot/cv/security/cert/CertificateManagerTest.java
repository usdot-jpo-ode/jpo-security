package gov.usdot.cv.security.cert;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.HashedId8;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.DecoderException;

import org.junit.BeforeClass;
import org.junit.Test;

import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

public class CertificateManagerTest {

	static final private boolean isDebugOutput = false;
	static final int publicCert = 1;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CertificateManager.clear();
	}

	@Test
	public void testCertificatesMap() throws DecoderException, EncodeFailedException, EncodeNotSupportedException {
		final String selfName = "Self";
		final String pcaName = "PCA";
		CertificateWrapper pcaCert = CertificateManager.get(pcaName);
		assertNull(pcaCert);
		
		pcaCert = MockCertificateStore.createCertificates()[publicCert];
		
		CertificateManager.put(pcaName, pcaCert);
		pcaCert = CertificateManager.get(pcaName);
		assertNotNull(pcaCert);
		assertNull(CertificateManager.get(selfName)); 
		
		HashedId8 pcaCertID8 = pcaCert.getCertID8();
		assertNotNull(pcaCertID8);
		CertificateWrapper pcaCert2 = CertificateManager.get(pcaCertID8);
		assertEquals(pcaCert, pcaCert2);
		
		CertificateManager.remove(pcaName);
		assertNull(CertificateManager.get(pcaName));
		assertNull(CertificateManager.get(pcaCertID8));
		
		CertificateManager.put(pcaCert);
		assertNull(CertificateManager.get(pcaName));
		assertNotNull(CertificateManager.get(pcaCertID8));
		
		CertificateManager.put(pcaName, pcaCert);
		assertNotNull(CertificateManager.get(pcaName));
		assertNotNull(CertificateManager.get(pcaCertID8));
		
		CertificateManager.remove(pcaCertID8);
		assertNotNull(CertificateManager.get(pcaName));
		assertNull(CertificateManager.get(pcaCertID8));
		
		CertificateManager.clear();
		assertNull(CertificateManager.get(pcaName));
		assertNull(CertificateManager.get(pcaCertID8));
	}
	
	@Test
	public void testRevocationList() throws DecoderException, EncodeFailedException, EncodeNotSupportedException {

		CertificateWrapper pcaCert = MockCertificateStore.createCertificates()[publicCert];
		assertNotNull(pcaCert);
		
		HashedId8 pcaCertID8 = pcaCert.getCertID8();
		assertNotNull(pcaCertID8);
				
		CertificateWrapper selfCert = MockCertificateStore.createCertificates()[publicCert];
		assertNotNull(selfCert);
		
		HashedId8 selfCertID8 = selfCert.getCertID8();
		assertNotNull(selfCertID8);
		
		assertFalse(CertificateManager.isRevoked(pcaCertID8));
		assertFalse(CertificateManager.isRevoked(pcaCert));
		assertFalse(CertificateManager.isRevoked(selfCertID8));
		assertFalse(CertificateManager.isRevoked(selfCert));
		
		List<HashedId8> revocationList = new ArrayList<HashedId8>();
		revocationList.add(selfCertID8);
		CertificateManager.set(revocationList);
		
		assertFalse(CertificateManager.isRevoked(pcaCert));
		assertFalse(CertificateManager.isRevoked(pcaCertID8));
		assertTrue(CertificateManager.isRevoked(selfCert));
		assertTrue(CertificateManager.isRevoked(selfCertID8));
		
		revocationList.add(pcaCertID8);
		CertificateManager.set(revocationList);
		
		assertTrue(CertificateManager.isRevoked(pcaCertID8));
		assertTrue(CertificateManager.isRevoked(pcaCert));
		assertTrue(CertificateManager.isRevoked(selfCertID8));
		assertTrue(CertificateManager.isRevoked(selfCert));
		
		CertificateManager.set(null);
		
		assertFalse(CertificateManager.isRevoked(pcaCert));
		assertFalse(CertificateManager.isRevoked(pcaCertID8));
		assertFalse(CertificateManager.isRevoked(selfCert));
		assertFalse(CertificateManager.isRevoked(selfCertID8));
	}

}
