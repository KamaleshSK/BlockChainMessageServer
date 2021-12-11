package com.Hermes.Server.Service;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

@Service
public class CommunicationClient {

	private static PrivateKey privateKey;
	private static PublicKey publicKey;
	private static PrivateKey encPrivateKey;
	private static PublicKey encPublicKey;
		
	static {
	    Security.addProvider(new BouncyCastleProvider());
	}
	
	CommunicationClient() {
		generateKeyPair();
		generateEncKeyPair();
	};
	
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	public PrivateKey getEncPrivateKey() {
		return encPrivateKey;
	}

	public PublicKey getEncPublicKey() {
		return encPublicKey;
	}
	
	public void generateEncKeyPair() {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			KeyPair kp = keyGen.generateKeyPair();
			encPublicKey = kp.getPublic();
			encPrivateKey = kp.getPrivate();
		} catch (NoSuchAlgorithmException e) {	
			e.printStackTrace();
		}
		
	}
	
	public void generateKeyPair() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA","BC");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
			// Initialize the key generator and generate a KeyPair
			keyGen.initialize(ecSpec, random); //256 
	        KeyPair keyPair = keyGen.generateKeyPair();
	        // Set the public and private keys from the keyPair
	        privateKey = keyPair.getPrivate();
	        publicKey = keyPair.getPublic();
	        
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public SecretKey generateRandomAES() throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(128); // The AES key size in number of bits
		SecretKey aesSymmetricKey = generator.generateKey();
		return aesSymmetricKey;
	}
	
	public String encrpytUsingAES(String inputJsonString, SecretKey aesSymmetricKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.ENCRYPT_MODE, aesSymmetricKey);
		byte[] byteCipherText = aesCipher.doFinal(inputJsonString.getBytes());
		return encode(byteCipherText);
	}
	
	public String encryptUsingRSA(SecretKey aesSymmetricKey, PublicKey recipientPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		
		// X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(recipientKey);
        // KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // publicKey = keyFactory.generatePublic(keySpecPublic);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.PUBLIC_KEY, recipientPublicKey);
		byte[] encryptedKey = cipher.doFinal(aesSymmetricKey.getEncoded());
		
		return encode(encryptedKey);
	}
	
	private static byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

	private static String encode(byte[] data) {
	    return Base64.getEncoder().encodeToString(data);
	}

	
}
