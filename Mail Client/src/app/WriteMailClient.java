package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.text.ParseException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;

import com.google.api.services.gmail.Gmail;

import keystore.KeyStoreReader;
import mailclient.MailBody;
import support.MailHelper;
import support.MailWritter;
import util.GzipUtil;
import util.IVHelper;
import util.Base64;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static short BLOCK_SIZE = 16;
	private static final String USER_A_JKS = "./data/usera.jks";
	private static final String USER_B_JKS = "./data/userb.jks";
	private static final String userBAlias = "userb";
	private static final String userAAlias = "usera";
	private static final String userBPass = "b";
	private static final String userAPass = "a";
	
	
	//kreiranje kljuca
		private static SecretKey generateKey() {
	        try {
				//generator para kljuceva za AES algoritam
				KeyGenerator   keyGen = KeyGenerator.getInstance("AES"); 
				//generise kljuc za AES, defaultne velicine od 128 bita
				SecretKey secretKey = keyGen.generateKey();
				return secretKey;
				
	        } catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
	        
	        return null;
		}

	public static void main(String[] args) {

		try {

			Gmail service = getGmailService();

			System.out.println("Insert a reciever:");
			BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			String reciever = reader.readLine();

			System.out.println("Insert a subject:");
			String subject = reader.readLine();

			System.out.println("Insert text:");
			String text = reader.readLine();

			// TODO: Compress and encrypt the content before sending.

			// compress
			String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
			String compressedText = Base64.encodeToString(GzipUtil.compress(text));

			 //generate Key
            SecretKey secretKey = generateKey();
            
            String encodedKey = Base64.encodeToString(secretKey.getEncoded());
            
            //javni kljuc korisnika B
            PublicKey publicKey = getPublicKey();

			// klasa za sifrovanje
            Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            
			// inicijalizacija za sifrovanje
        	IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
 			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
 			
 			
 			//sifrovanje
 			byte[] ciphertext = aesCipherEnc.doFinal(compressedText.getBytes());
 			String ciphertextStr = Base64.encodeToString(ciphertext);
 			System.out.println("Kriptovan tekst: " + ciphertextStr);
 			

 			//inicijalizacija za dekriptovanje
 			aesCipherEnc.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);
 			
 			 //inicijalizacija za sifrovanje 
 			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
 			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
 			
 			//sifrovanje
 			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
 			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
 			System.out.println("Kriptovan subject: " + ciphersubjectStr);
 			
 			//inicijalizacija za dekriptovanje
 			aesCipherEnc.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);
 			
 			
 			String encryptedAESKeyString = encryptAESKey(encodedKey, publicKey);
 			
 			

			// snimanje kljuca i IV
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
			

			MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, ciphertextStr);
			MailWritter.sendMessage(service, "me", mimeMessage);

		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	// iz usera.jks preuzeti sertifikat i javni ključ korisnika B
	private static PublicKey getPublicKey() {
		KeyStoreReader ksr = new KeyStoreReader();
		try {
			ksr.readKeyStore(USER_A_JKS, userBAlias, userAPass.toCharArray(), userBPass.toCharArray());
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		PublicKey pbk = ksr.readPublicKey();
		return pbk;
		
	}

	// Encrypt AES private Key using RSA public key
	private static String encryptAESKey(String encryptedAESKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.encodeToString(cipher.doFinal(encryptedAESKey.getBytes()));
    }
	

}
