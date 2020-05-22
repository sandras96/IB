package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;

	public static void main(String[] args) throws IOException {
		// Build a new authorized API client service.
		Gmail service = getGmailService();
		ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();

		String user = "me";
		String query = "is:unread label:INBOX";

		List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
		for (int i = 0; i < messages.size(); i++) {
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

		// TODO: Decrypt and decompress the message.

		try {
			Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");

			SecretKey secretKey = new SecretKeySpec(JavaUtils.getBytesFromFile(KEY_FILE), "AES");

			byte[] iv1 = JavaUtils.getBytesFromFile(IV1_FILE);
			IvParameterSpec ivParameterSpec1 = new IvParameterSpec(iv1);
			aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);

			String str = MailHelper.getText(chosenMessage);
			byte[] bodyEnc = Base64.decode(str);

			String receivedBodyTxt = new String(aesCipherDec.doFinal(bodyEnc));
			String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
			System.out.println("Body text: " + decompressedBodyText);

			byte[] iv2 = JavaUtils.getBytesFromFile(IV2_FILE);
			IvParameterSpec ivParameterSpec2 = new IvParameterSpec(iv2);
			// inicijalizacija za dekriptovanje
			aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);

			// dekompresovanje i dekriptovanje subject-a
			String decryptedSubjectTxt = new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
			String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
			System.out.println("Subject text: " + new String(decompressedSubjectTxt));

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
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
