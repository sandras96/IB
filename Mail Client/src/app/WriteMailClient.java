package app;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;

import support.MailHelper;
import support.MailWritter;
import util.GzipUtil;
import util.Base64;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";

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

			// create key
			// generator kljuceva za DES algoritam
			KeyGenerator keyGen = KeyGenerator.getInstance("DES");
			// generise kljuc za DES
			SecretKey secretKey = keyGen.generateKey();

			// klasa za sifrovanje
			Cipher desCipherEnc = Cipher.getInstance("DES/ECB/PKCS5Padding");
			// inicijalizacija za sifrovanje
			desCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
			// sifrovanje
			byte[] cipherSubject = desCipherEnc.doFinal(compressedSubject.getBytes());
			String cipherSubject1 = Base64.encodeToString(cipherSubject);

			byte[] cipherText = desCipherEnc.doFinal(compressedText.getBytes());
			String cipherText1 = Base64.encodeToString(cipherText);

			// snimanje kljuca
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());

			MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, cipherSubject1, cipherText1);
			MailWritter.sendMessage(service, "me", mimeMessage);

		} catch (Exception e) {
			e.printStackTrace();
		}

	}
}
