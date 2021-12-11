package com.Hermes.Server.Service;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.catalina.connector.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.Hermes.Server.Models.Message;
import com.Hermes.Server.Utils.JavaObjectToJson;
import com.Hermes.Server.Utils.Utils;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.OkHttpClient;
import okhttp3.Request;


@Service
public class EncryptAndSignMessage {

	@Autowired
	CommunicationClient communicationClient;
	
	@Autowired
	JavaObjectToJson javaObjectToJson;
	
	public Message getEncryptedAndSignedMessage(String messagePayload) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException, NoSuchProviderException {
		
		SecretKey randomSymmetricKey = communicationClient.generateRandomAES();
		String encryptedMessagePayload = communicationClient.encrpytUsingAES(messagePayload, randomSymmetricKey);
		
		OkHttpClient client = new OkHttpClient().newBuilder()
				  .build();
		Request request = new Request.Builder()
		  .url("http://localhost:8180/get-public-key")
		  .method("GET", null)
		  .build();
		okhttp3.Response response = client.newCall(request).execute();
		
		PublicKey recipientPublickey = Utils.getKeyFromString(response.body().string());
		
		PublicKey senderPublickey = communicationClient.getPublicKey();
		
		// encrypt randomSymmetricKey with recipientPublicKey
		String encryptedRandomSymmetricKey = communicationClient.encryptUsingRSA(randomSymmetricKey, recipientPublickey);
		
		byte[] signature = Utils.applyECDSASig(communicationClient.getPrivateKey(), Utils.getStringFromKey(senderPublickey) + Utils.getStringFromKey(recipientPublickey) + encryptedMessagePayload);
		
		Message message = new Message(encryptedRandomSymmetricKey, encryptedMessagePayload, signature, Utils.getStringFromKey(senderPublickey), Utils.getStringFromKey(recipientPublickey));
		
		return message;
	}
	
}
