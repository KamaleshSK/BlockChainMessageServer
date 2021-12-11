package com.Hermes.Server.Controllers;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.core.MessageSendingOperations;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.Hermes.Server.Service.CommunicationClient;
import com.Hermes.Server.Service.EncryptAndSignMessage;
import com.Hermes.Server.Utils.JavaObjectToJson;

@RestController
public class WSController {
	
	@Autowired
	EncryptAndSignMessage encryptAndSignMessage;
	
	@Autowired
	JavaObjectToJson javaObjectToJson;
	
	private final MessageSendingOperations<String> messageSendingOperations;

    public WSController(MessageSendingOperations<String> messageSendingOperations) {
        this.messageSendingOperations = messageSendingOperations;
    }

	@PostMapping("/send")
	public void sendMessage(@RequestBody String message) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NoSuchProviderException {
		
		String encryptedAndSignedMessage =  javaObjectToJson.convert(encryptAndSignMessage.getEncryptedAndSignedMessage(message));  
		this.messageSendingOperations.convertAndSend("/topic/periodic", encryptedAndSignedMessage);
	}
	
}
