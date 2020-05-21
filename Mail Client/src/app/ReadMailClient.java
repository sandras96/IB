package app;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;

public class ReadMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	//ucitavanje kljuca
	private static SecretKey loadSecretKey(String fileName) {

	    try {
			//Od bajtova se kreira DES specifikacija
	    	//bajtovi su od enkodiranog kljuca
	    	DESKeySpec keySpec = new DESKeySpec(JavaUtils.getBytesFromFile(fileName));
			//key factory transformise u objekat SecretKey
	    	SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
			SecretKey key = skf.generateSecret(keySpec);
			     
			return key;

	    } catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static void main(String[] args) throws IOException {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
	    @SuppressWarnings("unused")
		MimeMessage chosenMessage = mimeMessages.get(answer);
	    
        //TODO: Decrypt and decompress the message.
	    
	    try {
			Cipher desCipherDec = Cipher.getInstance("DES/ECB/PKCS5Padding");
			
			SecretKey secretKey = loadSecretKey(KEY_FILE);
			desCipherDec.init(Cipher.DECRYPT_MODE, secretKey);
			
			String text = MailHelper.getText(chosenMessage);
			byte [] receivedText = Base64.decode(text);
			
			String subject = chosenMessage.getSubject();
			byte [] receivedSubject = Base64.decode(subject);
			
			//dekriptovanje
			String receivedTxt = new String(desCipherDec.doFinal(receivedText));
			System.out.println("Primljeni text: " + new String(receivedTxt));
			
			String receivedSubject1 = new String(desCipherDec.doFinal(receivedSubject));
			System.out.println("Primljeni subject: " + new String(receivedSubject1));
		
			
			//decompress
			String decompressedText = GzipUtil.decompress(Base64.decode(receivedTxt));
			System.out.println("Primljeni text2: " + decompressedText);
			
			String decompressedSubject = GzipUtil.decompress(Base64.decode(receivedSubject1));
			System.out.println("Primljeni subject 2 je: " + decompressedSubject);

	    } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MessagingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	    
	}
	
	
}
