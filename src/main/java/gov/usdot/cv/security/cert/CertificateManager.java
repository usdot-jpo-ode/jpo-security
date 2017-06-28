package gov.usdot.cv.security.cert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.HashedId8;

/**
 * Process wide certificate manager
 *
 */
public final class CertificateManager {
	
	private static final int initialCapacity = 16;
	private static final float loadFactor = 0.9f;
	private static final int concurrencyLevel = 1; // let's keep it simple until we have some benchmarks with real loads
	
	// we want to be able to key on friendly certificate String name (i.e. CA, RA, Self, etc.) as well as BigInteger digest
	private static final ConcurrentHashMap<Object, CertificateWrapper> certificates = new ConcurrentHashMap<Object, CertificateWrapper>(initialCapacity, loadFactor, concurrencyLevel);

	private static final Set<HashedId8> revocationList = Collections.newSetFromMap(new ConcurrentHashMap<HashedId8,Boolean>(initialCapacity, loadFactor, concurrencyLevel));
	
	/**
	 * Register the certificate with the certificate manager using its digest
	 * @param certificate to register
	 */
	public static void put(CertificateWrapper certificate) {
		assert(certificate != null);
		certificates.put(certificate.getCertID8(), certificate);
	}
	
	/**
	 * Register the certificate with the certificate manager using friendly name
	 * @param name of the certificate to register
	 * @param certificate  to register
	 */
	public static void put(String name, CertificateWrapper certificate) {
		assert(name != null && certificate != null);
		certificates.put(name, certificate);
		put(certificate);
	}
	
	/**
	 * Register the certificate with the certificate manager if it is not already registered
	 * @param certID8 digest of the certificate to register
	 * @param certificate to register
	 */
	public static synchronized void put(HashedId8 certID8, CertificateWrapper certificate) {
		if ( CertificateManager.get(certID8) == null )
			CertificateManager.put(certificate);
	}
	
	/**
	 * Retrieves a certificate by digest
	 * @param certID8 digest of the certificate to retrieve
	 * @return the certificate specified by digest or null if one is not found
	 */
	public static CertificateWrapper get(HashedId8 certID8) {
		assert(certID8 != null);
		return certificates.get(certID8);
	}
	
	/**
	 * Retrieves a certificate by friendly name
	 * @param name of the certificate to retrieve
	 * @return the certificate specified by digest or null if one is not found
	 */
	public static CertificateWrapper get(String name) {
		assert(name != null);
		return certificates.get(name);
	}
	
	/**
	 * Removes a certificate by digest
	 * @param certID8 digest of the certificate to remove
	 */
	public static void remove(HashedId8 certID8) {
		assert(certID8 != null);
		certificates.remove(certID8);
	}
	
	/**
	 * Removes a certificate by friendly name.  This will also
	 * remove the certificate from the manager based on its digest
	 * @param name of the certificate to remove
	 */
	public static void remove(String name) {
		assert(name != null);
		CertificateWrapper certificate = certificates.remove(name);
		if ( certificate != null ) 
			certificates.remove(certificate.getCertID8());
	}
	
	/**
	 * Unregister all certificates
	 */
	public static void clear() {
		certificates.clear();
	}
	
	/**
	 * Assign new revocation list or null to clear the list
	 * @param newRevocationList a list of HashedId8 of the certificates that have been revoked
	 */
	public static void set(List<HashedId8> newRevocationList) {
		revocationList.clear();
		if (newRevocationList == null) {
			return;
		}
		List<HashedId8> intRevocationList = new ArrayList<HashedId8>(newRevocationList.size());
		for(HashedId8 certId8 : newRevocationList) {
			intRevocationList.add(certId8);
		}
		revocationList.addAll(intRevocationList);
	}
	
	/**
	 * Verifies whether a certificate has been revoked
	 * @param certificate of interest
	 * @return true if the certificate has been revoked and false otherwise
	 */
	public static boolean isRevoked(CertificateWrapper certificate) {
		return certificate != null ? isRevoked(certificate.getCertID8()) : false;
	}
	
	/**
	 * Verifies whether a certificate with the specified digest has been revoked
	 * @param certID8 digest of the certificate of interest
	 * @return true if the certificate has been revoked and false otherwise
	 */
	public static boolean isRevoked(HashedId8 certID8) {
		return certID8 != null ? revocationList.contains(certID8) : false;
	}

}
