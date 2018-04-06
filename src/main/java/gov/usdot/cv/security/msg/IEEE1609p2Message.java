package gov.usdot.cv.security.msg;

import java.security.interfaces.ECPrivateKey;
import java.util.Date;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;
import com.oss.asn1.OctetString;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.AesCcmCiphertext;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.EncryptedData;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.EncryptedDataEncryptionKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.HeaderInfo;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.Ieee1609Dot2Content;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.Ieee1609Dot2Data;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.PKRecipientInfo;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.RecipientInfo;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SequenceOfCertificate;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SequenceOfRecipientInfo;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SignedData;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SignedDataPayload;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SignerIdentifier;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SymmetricCiphertext;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.ToBeSignedData;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EciesP256EncryptedKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.HashAlgorithm;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.HashedId8;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Opaque;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Psid;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Signature;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.ThreeDLocation;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Time64;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Uint8;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.cert.CertificateWrapper;
import gov.usdot.cv.security.cert.SecureECPrivateKey;
import gov.usdot.cv.security.clock.ClockHelper;
import gov.usdot.cv.security.crypto.AESProvider;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoHelper;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.EcdsaP256SignatureWrapper;
import gov.usdot.cv.security.util.Ieee1609dot2Helper;
import gov.usdot.cv.security.util.Time64Helper;

/**
 * Instance of an IEEE 1609.2 Message
 *
 */
public class IEEE1609p2Message {
	
	private static final Logger log = Logger.getLogger(IEEE1609p2Message.class);
	
	private static String selfCertificateFriendlyName  = "Self";

	/**
	 * CryptoProvider to be used for all cryptographic operations by this instance
	 */
	protected final CryptoProvider cryptoProvider;
	
	/**
	 * CryptoHelper to be used for all cryptographic operations by this instance
	 */
	protected final CryptoHelper cryptoHelper;
	
	static private final Uint8 protocolVersion = new Uint8(3);
	
	private CertificateWrapper selfCertificate = CertificateManager.get(IEEE1609p2Message.selfCertificateFriendlyName);
	
	private CertificateWrapper certificateWrapper;
	private HashedId8 certID8;
	private Psid psid;
	private SignedDataPayload payload;
	private Time64 generationTime;
	private Time64 expiryTime;
	static SignerIdentifier signerId;

	/**
	 * Private constructor which will create cryptographic provider
	 */
	public IEEE1609p2Message() {
		this(null);
	}
	
	/**
	 * Private constructor with explicit cryptographic provider
	 * @param cryptoProvider the provider
	 */
	public IEEE1609p2Message(CryptoProvider cryptoProvider) {
		if ( cryptoProvider == null  )
			cryptoProvider = new CryptoProvider();
		this.cryptoProvider = cryptoProvider;
		this.cryptoHelper = new CryptoHelper(cryptoProvider);
	}
	
	/**
	 * Creates IEEE 1609.2 Message from bytes
	 * @param msgBytes message bytes (typically received over UDP)
	 * @return IEEE1609p2Message instance
	 * @throws MessageException if bytes do not represent an IEEE 1609.2 Message
	 * @throws CertificateException if certificate in the message is not valid
	 * @throws CryptoException if symmetric decryption fails
	 * @throws EncodeNotSupportedException if encoding is not supported
	 * @throws EncodeFailedException if encoding failed
	 */
	static public IEEE1609p2Message parse(byte[] msgBytes) throws MessageException, CertificateException, CryptoException,
																	EncodeFailedException, EncodeNotSupportedException {
		return parse(msgBytes, new CryptoProvider());
	}
	
	/**
	 * Creates IEEE 1609.2 Message from bytes with explicit cryptographic provider
	 * @param msgBytes message bytes (typically received over UDP)
	 * @param cryptoProvider thread wide cryptographic provider instance
	 * @return IEEE1609p2Message instance
	 * @throws MessageException if bytes do not represent an IEEE 1609.2 Message
	 * @throws CertificateException if certificate in the message is not valid
	 * @throws CryptoException if symmetric decryption fails
	 * @throws EncodeNotSupportedException if encoding is not supported
	 * @throws EncodeFailedException if encoding failed
	 */
	static public IEEE1609p2Message parse(byte[] msgBytes, CryptoProvider cryptoProvider)
																	throws MessageException, CertificateException, CryptoException,
																			EncodeFailedException, EncodeNotSupportedException {
		if(msgBytes == null) {
			return null;
		}
		if(msgBytes.length < 80) {
			throw new MessageException(String.format("Parameter bytes are too short. Buffer bytes: %d.", msgBytes.length));
		}
		
		try {
			Ieee1609Dot2Data message = Ieee1609dot2Helper.decodeCOER(msgBytes, new Ieee1609Dot2Data());
			Uint8 version = message.getProtocolVersion();
			if(!version.equalTo(protocolVersion)) {
				throw new MessageException(
							String.format("Unexpected Protocol Version value. Expected %d, Actual: %d.",
											version,
											protocolVersion.intValue()));
			}
			
			Ieee1609Dot2Content content = message.getContent();
			if (content.hasSignedData()) {
				return parseSigned(content.getSignedData(), cryptoProvider);
			}
			else if(content.hasEncryptedData()) {
				return parseEncrypted(content.getEncryptedData(), cryptoProvider);
			}
			else {
				throw new MessageException(String.format("Unexpected Content Type value %d.", content.getChosenFlag()));
			}
		} catch (DecodeFailedException | DecodeNotSupportedException e) {
			throw new MessageException("Failed to decode message from bytes.", e);
		}
	}
	
    /**
     * Creates IEEE 1609.2 Message from Ieee1609Dot2Data with explicit cryptographic provider
     * @param message Ieee1609Dot2Data
     * @return IEEE1609p2Message instance
     * @throws MessageException if bytes do not represent an IEEE 1609.2 Message
     * @throws CertificateException if certificate in the message is not valid
     * @throws CryptoException if symmetric decryption fails
     * @throws EncodeNotSupportedException if encoding is not supported
     * @throws EncodeFailedException if encoding failed
     */
    static public IEEE1609p2Message convert(Ieee1609Dot2Data message) 
                throws MessageException, EncodeFailedException, CertificateException, EncodeNotSupportedException, CryptoException {
        if(message == null) {
            return null;
        }
        
        CryptoProvider cryptoProvider = new CryptoProvider();
        
        Uint8 version = message.getProtocolVersion();
        if(!version.equalTo(protocolVersion)) {
            throw new MessageException(
                        String.format("Unexpected Protocol Version value. Expected %d, Actual: %d.",
                                        version,
                                        protocolVersion.intValue()));
        }
        
        Ieee1609Dot2Content content = message.getContent();
        if (content.hasSignedData()) {
            return parseSigned(content.getSignedData(), cryptoProvider);
        }
        else if(content.hasEncryptedData()) {
            return parseEncrypted(content.getEncryptedData(), cryptoProvider);
        }
        else {
            throw new MessageException(String.format("Unexpected Content Type value %d.", content.getChosenFlag()));
        }
    }
    
	/**
	 * Creates IEEE 1609.2 Message from signed data with explicit cryptographic provider
	 * @param signedData  signed data to parse
	 * @param cryptoProvider cryptographic provider to use
	 * @return IEEE1609p2Message instance
	 * @throws MessageException if bytes do not represent an IEEE 1609.2 Message
	 * @throws CertificateException if certificate in the message is not valid
	 * @throws EncodeNotSupportedException if encoding is not supported
	 * @throws EncodeFailedException if encoding failed 
	 */
	static private IEEE1609p2Message parseSigned(SignedData signedData, CryptoProvider cryptoProvider)
																	throws MessageException, CertificateException, 
																			EncodeFailedException, EncodeNotSupportedException {
		
		IEEE1609p2Message msg = new IEEE1609p2Message(cryptoProvider);
		
		signerId = signedData.getSigner();
		if(signerId.hasDigest()) {
			msg.certID8 = signerId.getDigest();
			msg.certificateWrapper = CertificateManager.get(msg.certID8);
		}
		else if(signerId.hasCertificate()) {
			// TODO: (6.3.24)
			// Previously handled case where only one certificate was provided and ignored case with chain of certificates.
			// New standard only has case for chain of certificates where:
			//    - The structure contains one or more Certificate structures, in order such that the first certificate
			//      is the authorization certificate and each subsequent certificate is the issuer of the one before it.
			//    - The verification type is certificate and the certificate data passed to the hash function as
			//    - specified in 5.3.1 is the authorization certificate.
			//
			// For now, assume that we only use the first certificate in the chain as the authorization certificate
			msg.certificateWrapper = CertificateWrapper.fromCertificate(msg.cryptoProvider, signerId.getCertificate().get(0));
			msg.certID8 = msg.certificateWrapper.getCertID8();
		}
		else {
			throw new MessageException(String.format("Unexpected Signer ID type value %d.", signerId.getChosenFlag()));
		}
		
		// validate client certificate
		msg.validateCertificate();
		
		ToBeSignedData tbsData = signedData.getTbsData();
		
		HeaderInfo tbsHeaderInfo = tbsData.getHeaderInfo();
		
		msg.psid = tbsHeaderInfo.getPsid();
		log.debug(String.format("psid: 0x%x", msg.psid.intValue()));
		if (msg.psid.intValue() == -1) {
			throw new MessageException(String.format("Couldn't decode PSID value. See log file for details."));
		}
		
		msg.payload = tbsData.getPayload();
		log.debug("payload: " + msg.payload);
		
		if(tbsHeaderInfo.hasGenerationTime()) {
			msg.generationTime = tbsHeaderInfo.getGenerationTime();
			log.debug(String.format("Generation Time: %s", Time64Helper.time64ToDate(msg.generationTime)));
			
		}
		
		if(tbsHeaderInfo.hasExpiryTime()) {
			msg.expiryTime = tbsHeaderInfo.getExpiryTime();
			log.debug("Expiry Time: " + Time64Helper.time64ToDate(msg.expiryTime));
			
		}
		
		if(tbsHeaderInfo.hasGenerationLocation()) {
			ThreeDLocation threeDLocation = tbsHeaderInfo.getGenerationLocation();
			log.debug("Generation Location: " + threeDLocation);
			
		}
		
		// Validate signature
		try {
			byte[] tbsDataBytes = Ieee1609dot2Helper.encodeCOER(tbsData);
			byte[] signingCertificateBytes = msg.certificateWrapper.getBytes();
			EcdsaP256SignatureWrapper signature = EcdsaP256SignatureWrapper.decode(signedData.getSignature(), cryptoProvider.getSigner());
			ECPublicKeyParameters signingPublicKey = msg.certificateWrapper.getSigningPublicKey();
			if ( !msg.cryptoHelper.verifySignature(tbsDataBytes, signingCertificateBytes, signingPublicKey, signature) ) {
				log.error("Message signature is not valid");
				throw new MessageException("Message signature is not valid");
			}
		} catch (EncodeFailedException | EncodeNotSupportedException e) {
			throw new MessageException("Failed to encode ToBeSignedData for signature validation.", e);
		}

		return msg;
	}
	
	/**
	 * Creates IEEE 1609.2 Message from encyrpted data with explicit cryptographic provider
	 * @param encryptedData encrypted data to parse
	 * @param cryptoProvider cryptographic provider to use
	 * @return IEEE1609p2Message instance
	 * @throws MessageException if bytes do not represent an IEEE 1609.2 Message
	 * @throws CertificateException if certificate in the message is not valid
	 * @throws CryptoException if decryption fails
	 * @throws EncodeNotSupportedException if encoding is not supported
	 * @throws EncodeFailedException if encoding failed
	 */
	static private IEEE1609p2Message parseEncrypted(EncryptedData encryptedData, CryptoProvider cryptoProvider)
																	throws MessageException, CertificateException, CryptoException,
																			EncodeFailedException, EncodeNotSupportedException {

		IEEE1609p2Message msg = new IEEE1609p2Message(cryptoProvider);

		if(!encryptedData.getCiphertext().hasAes128ccm()) {
			throw new MessageException(String.format("Unexpected symmetric algorithm value. Expected %d, Actual: %d.",
														SymmetricCiphertext.aes128ccm_chosen,
														encryptedData.getCiphertext().getChosenFlag()));
		}
	
		HashedId8 msgCertId8 = msg.getSelfCertificate().getCertID8();
		CertificateWrapper msgCert = CertificateManager.get(msgCertId8);
		SecureECPrivateKey msgCertEncryptionPrivateKey = null;
		if (msgCert != null ) {
			msgCertEncryptionPrivateKey = msgCert.getEncryptionPrivateKey();
			if (msgCertEncryptionPrivateKey == null)
				log.info(String.format("Certificate for CertID8 %s does not contain private encryption key",
											Hex.encodeHexString(msgCertId8.byteArrayValue())));
		} else {
			log.info(String.format("Certificate for CertID8 %s was not found", Hex.encodeHexString(msgCertId8.byteArrayValue())));
		}
		
		KeyParameter symmetricKey = null;
		for(int i = 0; i < encryptedData.getRecipients().getSize(); i++) {
			RecipientInfo recipientInfo = encryptedData.getRecipients().get(i);
			
			if(recipientInfo.hasCertRecipInfo()) {
				PKRecipientInfo certRecipientInfo = recipientInfo.getCertRecipInfo();

				// Only try to grab the key if the recipient is this msg
				if(msgCertId8.equalTo(certRecipientInfo.getRecipientId())) {
					EciesP256EncryptedKey eciesP256EncryptedKey = (certRecipientInfo.getEncKey().hasEciesNistP256())?
																			(certRecipientInfo.getEncKey().getEciesNistP256()):
																			(certRecipientInfo.getEncKey().getEciesBrainpoolP256r1());

					try {
						symmetricKey = cryptoProvider.getECIESProvider().decodeEciesP256EncryptedKey(
						   eciesP256EncryptedKey, msgCertEncryptionPrivateKey);
					} catch (Exception ex) {
						log.error(String.format("Decoding symmetric key failed for %s. Reason: %s",
													Hex.encodeHexString(msgCertId8.byteArrayValue()), ex.getMessage(), ex));
					}
					if (symmetricKey != null) {
						break;
					}
				}
			}
			else {
				log.info(String.format("Expected recipient info of type %d. Ignoring recipient info of type %d.",
												RecipientInfo.certRecipInfo_chosen,
												recipientInfo.getChosenFlag()));
			}
		}
		if (symmetricKey == null) {
			throw new MessageException("Coulnd't retrieve symmetric encryption key from the sequence of recipient information");
		}

		AesCcmCiphertext cipherText = encryptedData.getCiphertext().getAes128ccm();
		
		CryptoHelper helper = new CryptoHelper(cryptoProvider);
		byte[] clearText = helper.decryptSymmetric(symmetricKey, cipherText);
		
		// clearText is a Ieee1609Dot2Data with signed data content
		try {
			Ieee1609Dot2Data ieee1609Dot2Data = Ieee1609dot2Helper.decodeCOER(clearText, new Ieee1609Dot2Data());
			msg = parseSigned(ieee1609Dot2Data.getContent().getSignedData(), cryptoProvider);
		} catch (DecodeFailedException | DecodeNotSupportedException e) {
			throw new MessageException("Failed to encode SignedData for parsing.", e);
		}
		
		return msg;
	}
	
	/**
	 * Sign and encode 1609.2 message with self public certificate as signer identifier
	 * @param payloadBytes payload message data
	 * @return encoded signed message bytes
	 * @throws EncodeNotSupportedException if encoding fails
	 * @throws EncodeFailedException if encoding fails
	 * @throws CertificateException if self certificate was not found
	 * @throws CryptoException if encoding of signature fails
	 */
	public byte[] sign(byte[] payloadBytes) throws EncodeFailedException, EncodeNotSupportedException, CertificateException, CryptoException {
		return sign(payloadBytes, true);
	}
	
	/**
	 * Sign and encode 1609.2 message
	 * @param payloadBytes payload message data
	 * @param withCertificate if true use self public certificate as signer identifier, otherwise use CertID8 digest
	 * @return encoded signed message bytes
	 * @throws EncodeNotSupportedException if encoding fails
	 * @throws EncodeFailedException if encoding fails
	 * @throws CertificateException if self certificate was not found
	 * @throws CryptoException if encoding of signature fails
	 */
	public byte[] sign(byte[] payloadBytes, boolean withCertificate) 
																	throws EncodeFailedException, EncodeNotSupportedException,
																			CertificateException, CryptoException {
		// Use this certificate as the signer
		certificateWrapper = getSelfCertificate();
		
		// Create the ToBeSignedData
		HeaderInfo tbsHeaderInfo = new HeaderInfo();
		tbsHeaderInfo.setPsid(psid);
		generationTime = Time64Helper.dateToTime64(ClockHelper.nowDate()); 
		tbsHeaderInfo.setGenerationTime(generationTime);
		 
		payload = createSignedDataPayload(payloadBytes);
		
		ToBeSignedData tbsData = new ToBeSignedData(payload, tbsHeaderInfo);
		
		// Create the Signer
		SignerIdentifier signer;
		if(withCertificate) {
			// TODO: Previous standard allowed option to use only one certificate instead of a sequence.
			// This version allows only a sequence.  For now, only add our certificate to the sequence.
			SequenceOfCertificate seqOfCert = new SequenceOfCertificate();
			seqOfCert.add(certificateWrapper.getCertificate());
			signer = SignerIdentifier.createSignerIdentifierWithCertificate(seqOfCert);
		}
		else {
			signer = SignerIdentifier.createSignerIdentifierWithDigest(certificateWrapper.getCertID8());
		}
		
		// Create the signature
		byte[] tbsDataBytes = Ieee1609dot2Helper.encodeCOER(tbsData);
		EcdsaP256SignatureWrapper ecdsaP256Signature = 
									cryptoHelper.computeSignature(tbsDataBytes,
																	certificateWrapper.getBytes(),
																	(ECPrivateKey) certificateWrapper.getSigningPrivateKey().getKey());
		Signature signature = ecdsaP256Signature.encode();
		
		// Package them all together as Ieee1609Dot2Data with SignedData Content
		SignedData signedData = new SignedData(HashAlgorithm.sha256, tbsData, signer, signature);
		Ieee1609Dot2Content content = Ieee1609Dot2Content.createIeee1609Dot2ContentWithSignedData(signedData);
		Ieee1609Dot2Data data = new Ieee1609Dot2Data(protocolVersion, content);
		
		// Encode the data
		byte[] dataBytes = Ieee1609dot2Helper.encodeCOER(data);
		
		return dataBytes;
	}
	
	/**
	 * Encode data as SignedDataPayload (6.3.7)
	 * @param unsecuredData  bytes to encode as payload
	 * @return encoded SignedDataPayload
	 */
	private SignedDataPayload createSignedDataPayload(byte[] unsecuredData) {
		Opaque opaque = new Opaque(unsecuredData);
		Ieee1609Dot2Content content = Ieee1609Dot2Content.createIeee1609Dot2ContentWithUnsecuredData(opaque);
		Ieee1609Dot2Data data = new Ieee1609Dot2Data(protocolVersion, content);
		
		SignedDataPayload payload = new SignedDataPayload();
		payload.setData(data);
		
		return payload;
	}

	/**
	 * Encrypt and encode 1609.2 message with signer id digest
	 * @param payload payload message data
	 * @param recipients variable argument list of HashedId8 for recipients
	 * @return encoded encrypted 1609.2 message
	 * @throws CertificateException  if recipient certificate can not be found
	 * @throws CryptoException if symmetric encryption fails
	 * @throws EncodeNotSupportedException if the signing of the payload fails
	 * @throws EncodeFailedException if the signing of the payload fails
	 * @throws InvalidCipherTextException if the encoding of the EciesP256EncryptedKey fails
	 */
	public byte[] encrypt(byte[] payload, HashedId8 ... recipients) throws CertificateException, CryptoException, EncodeFailedException,
																			EncodeNotSupportedException, InvalidCipherTextException {
		return encrypt(payload, false, recipients);
	}
	
	/**
	 * Encrypted and encode 1609.2 message
	 * @param payload payload message data
	 * @param withCertificate if true signer id will be certificate, otherwise digest
	 * @param recipients variable argument list of HashedId8 for recipients
	 * @return encoded encrypted 1609.2 message
	 * @throws CertificateException if recipient certificate can not be found
	 * @throws CryptoException if symmetric encryption fails
	 * @throws EncodeNotSupportedException if the signing of the payload fails
	 * @throws EncodeFailedException if the signing of the payload fails
	 * @throws InvalidCipherTextException if the encoding of the EciesP256EncryptedKey fails
	 */
	public byte[] encrypt(byte[] payload, boolean withCertificate, HashedId8 ... recipients)
													throws CertificateException, CryptoException, EncodeFailedException,
															EncodeNotSupportedException, InvalidCipherTextException {

		KeyParameter symmetricKey = AESProvider.generateKey();
		
		SequenceOfRecipientInfo seqOfRecipients = new SequenceOfRecipientInfo();
		for(HashedId8 recipient : recipients) {
			
			CertificateWrapper certificate = CertificateManager.get(recipient);
			if ( certificate == null ) {
				throw new CertificateException(
						String.format("Certificate for recipient %s was not found", Hex.encodeHexString(recipient.byteArrayValue())));
			}
			
			ECPublicKeyParameters recipientEncryptionPublicKey = certificate.getEncryptionPublicKey();
			if (recipientEncryptionPublicKey == null) {
				throw new CertificateException(String.format("Certificate for recipient %s does not contain public encryption key",
																Hex.encodeHexString(recipient.byteArrayValue())));
			}
			
			EciesP256EncryptedKey eciesP256EncryptedKey = cryptoProvider.getECIESProvider().encodeEciesP256EncryptedKey(symmetricKey, recipientEncryptionPublicKey);
			EncryptedDataEncryptionKey encKey = EncryptedDataEncryptionKey.createEncryptedDataEncryptionKeyWithEciesNistP256(eciesP256EncryptedKey);
			
			PKRecipientInfo certRecipInfo = new PKRecipientInfo();
			certRecipInfo.setRecipientId(recipient);
			certRecipInfo.setEncKey(encKey);
			
			RecipientInfo recipientInfo = RecipientInfo.createRecipientInfoWithCertRecipInfo(certRecipInfo);
			seqOfRecipients.add(recipientInfo);
		}
		
		byte[] clearText = sign(payload, withCertificate);
		
		CryptoHelper helper = new CryptoHelper(cryptoProvider);
		
		byte[] nonceBytes = CryptoHelper.getSecureRandomBytes(AESProvider.nonceLength);
		OctetString nonce = new OctetString(nonceBytes);
		
		byte[] ccmCipherTextBytes = helper.encryptSymmetric(symmetricKey, nonceBytes, clearText);
		Opaque ccmCiphertext = new Opaque(ccmCipherTextBytes);
		
		AesCcmCiphertext aesCcmCiphertext = new AesCcmCiphertext(nonce, ccmCiphertext);
		
		SymmetricCiphertext ciphertext = SymmetricCiphertext.createSymmetricCiphertextWithAes128ccm(aesCcmCiphertext);
		
		EncryptedData encryptedData = new EncryptedData(seqOfRecipients, ciphertext);
		
		Ieee1609Dot2Content content = Ieee1609Dot2Content.createIeee1609Dot2ContentWithEncryptedData(encryptedData);

		Ieee1609Dot2Data data = new Ieee1609Dot2Data(protocolVersion, content);
		
		byte[] encryptedDataBytes = Ieee1609dot2Helper.encodeCOER(data);

		return encryptedDataBytes;
	}

	/**
	 * Retrieves Provider Service Identifier for this message
	 * @return Provider Service Identifier value
	 */
	public Integer getPSID() {
		return psid.intValue();
	}

	/**
	 * Assigns Provider Service Identifier for this message
	 * @param psid new Assigns Provider Service Identifier value
	 */
	public void setPSID(Integer psid) {
		this.psid = new Psid(psid);
	}
	
	/**
	 * Retrieves payload bytes from the message
	 * @return payload bytes as clear text
	 */
	public byte[] getPayload() {
		return payload.getData().getContent().getUnsecuredData().byteArrayValue();
	}

    /**
     * Retrieves Ieee1609Dot2Data from the message
     * @return Ieee1609Dot2Data
     */
    public Ieee1609Dot2Data getIeee1609Dot2Data() {
        return payload.getData();
    }

	/**
	 * Retrieves sender's public certificate
	 * @return sender's public certificate or null in one is not present in the message
	 */
	public CertificateWrapper getCertificate() {
		return certificateWrapper;
	}
	
	/**
	 * Retrieves sender's certificate digest
	 * @return sender's certificate digest or null in one is not present in the message
	 */
	public HashedId8 getCertID8() {
		return certID8;
	}
	
	/**
	 * Retrieves message generation time
	 * @return message generation time as Date
	 */
	public Date getGenerationTime() {
		return Time64Helper.time64ToDate(generationTime);
	}
	
	/**
	 * Retrieves the SignerIdentifier of the message
	 * @return SignerIdentifier of the message
	 */
	public SignerIdentifier getSignerId() {
		return signerId;
	}
	
	/**
	 * Validates the message's certificate
	 * @throws CertificateException if certificate is not valid
	 */
	private void validateCertificate() throws CertificateException {
		if(certID8 == null) {
			throw new CertificateException("Required certID8 is missing.");
		}
		
		if(certificateWrapper == null) {
			throw new CertificateException(String.format("Certificate for provided CertID8 %s is missing.", 
																Hex.encodeHexString(certID8.byteArrayValue())));
		}

		if (certificateWrapper.isValid()) {
			CertificateManager.put(certID8, certificateWrapper);
		} else {
			CertificateManager.remove(certID8);
			throw new CertificateException(String.format("Certificate for CertID8 %s is not valid",
															Hex.encodeHexString(certID8.byteArrayValue())));
		}
	}
	
	/**
	 * Assigns global certificate store friendly certificate name for this entity.
	 * Note that all existing instances will continue using the selfCertificate that was in place when they were created
	 * @param friendlyName friendly certificate name to assign
	 */
	static public void setSelfCertificateFriendlyName(String friendlyName) {
		selfCertificateFriendlyName  = friendlyName;
		log.debug(String.format("New self certificate friendly name: '%s'", selfCertificateFriendlyName));
	}
	
    static public String getSelfCertificateFriendlyName() {
        return selfCertificateFriendlyName;
    }
    
	/**
	 * Retrieves self certificate.
	 * The certificate is always a public certificate with private keys set after it has been instantiated. 
	 * In other words, it has private keys but getBytes() returns a public certificate that only has public keys
	 * and thus is suitable for adding to a message as signer ID.
	 * @return self certificate
	 * @throws CertificateException 
	 */
	private CertificateWrapper getSelfCertificate() throws CertificateException {
		if (selfCertificate == null) {
			synchronized(this) {
				if (selfCertificate == null) {
					selfCertificate = CertificateManager.get(IEEE1609p2Message.selfCertificateFriendlyName);
					if ( selfCertificate == null )
						throw new CertificateException(String.format("Self certificate with name '%s' was not found", IEEE1609p2Message.selfCertificateFriendlyName));
				}
			}
		}

		return selfCertificate;
	}

}
