package app;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.implementations.RSAKeyValueResolver;
import org.apache.xml.security.keys.keyresolver.implementations.X509CertificateResolver;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import keystore.IssuerData;
import keystore.KeyStoreReader;
import mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;

public class ReadMailClient extends MailClient {

	private static final String USER_B_JKS = "./data/userb.jks";
	private static final String userAAlias = "usera";
	private static final String userBAlias = "userb";
	private static final String userBPass = "b";
	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;

	static {
		// staticka inicijalizacija
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}

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

		try {

			// izvlacenje teksta mail-a koji je trenutno u obliku stringa
			String xmlAsString = MailHelper.getText(chosenMessage);

			// kreiranje XML dokumenta na osnovu stringa
			Document doc = createXMlDocument(xmlAsString);

			Element element = (Element) doc.getElementsByTagName("mail").item(0);

			// citanje keystore-a kako bi se izvukao sertifikat primaoca
			// i kako bi se dobio njegov tajni kljuc
			PrivateKey privateKey = getPrivateKey();

			// desifrovanje tajnog (session) kljuca pomocu privatnog kljuca
			XMLCipher xmlCipher = XMLCipher.getInstance();
			xmlCipher.init(XMLCipher.DECRYPT_MODE, null);

			// trazi se prvi EncryptedData element i izvrsi dekriptovanje
			EncryptedData encryptedData = xmlCipher.loadEncryptedData(doc, element);
			KeyInfo keyinfo = encryptedData.getKeyInfo();
			EncryptedKey encKey = keyinfo.itemEncryptedKey(0);

			XMLCipher keyCipher = XMLCipher.getInstance();
			keyCipher.init(XMLCipher.UNWRAP_MODE, privateKey);
			Key key = keyCipher.decryptKey(encKey, encryptedData.getEncryptionMethod().getAlgorithm());
			xmlCipher.init(XMLCipher.DECRYPT_MODE, key);
			xmlCipher.setKEK(key);

			// dekriptuje se
			// pri cemu se prvo dekriptuje tajni kljuc, pa onda njime podaci
			xmlCipher.doFinal(doc, element, true);

			// provera potpisa
			ReadMailClient verify = new ReadMailClient();
			verify.verify(doc);

			String msg = doc.getElementsByTagName("mailSubject").item(0).getTextContent();
			System.out.println("\nSubject text: " + (msg.split("\n"))[0]);
			String msg1 = doc.getElementsByTagName("mailBody").item(0).getTextContent();
			System.out.println("Body text: " + (msg1.split("\n"))[0]);

		} catch (MessagingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (XMLEncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}

	// Iz sertifikata korisnika B izvuci njegov tajni kljuc
	private static PrivateKey getPrivateKey() {
		KeyStoreReader keyStoreReader = new KeyStoreReader();
		IssuerData issuerData = null;

		try {
			issuerData = keyStoreReader.readKeyStore(USER_B_JKS, userBAlias, userBPass.toCharArray(),
					userBPass.toCharArray());
			PrivateKey privateKey = issuerData.getPrivateKey();
			return privateKey;
		} catch (ParseException e) {
			e.printStackTrace();
		}

		return null;
	}


	// kreiranje dokumenta od xml fajla koji je kao string
	private static Document createXMlDocument(String xmlAsString) {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder;
		Document doc = null;
		try {
			builder = factory.newDocumentBuilder();
			doc = builder.parse(new InputSource(new StringReader(xmlAsString)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return doc;
	}

	public void verify(Document doc) {
		boolean res = verifySignature(doc);
		System.out.println("\nVerification = " + res);
	}

	private static boolean verifySignature(Document doc) {
		try {
			// Pronalazi se prvi Signature element
			NodeList signatures = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
			Element signatureEl = (Element) signatures.item(0);

			// kreira se signature objekat od elementa
			XMLSignature signature = new XMLSignature(signatureEl, null);

			// preuzima se key info
			KeyInfo keyInfo = signature.getKeyInfo();

			// ako postoji
			if (keyInfo != null) {
				// registruju se resolver-i za javni kljuc i sertifikat
				keyInfo.registerInternalKeyResolver(new RSAKeyValueResolver());
				keyInfo.registerInternalKeyResolver(new X509CertificateResolver());

				// ako sadrzi sertifikat
				if (keyInfo.containsX509Data() && keyInfo.itemX509Data(0).containsCertificate()) {
					X509Certificate cert = (X509Certificate) readCertificate();
					// ako postoji sertifikat, provera potpisa
					if (cert != null) {
						if (signature.checkSignatureValue((X509Certificate) cert))
							return true;
						else
							return false;
					} else
						return false;
				} else
					return false;
			} else
				return false;

		} catch (XMLSignatureException e) {
			e.printStackTrace();
			return false;
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			return false;
		}
	}

	private static X509Certificate readCertificate() {
		try {
			// kreiramo instancu KeyStore
			KeyStore ks = KeyStore.getInstance("JKS", "SUN");

			// ucitavamo podatke
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(USER_B_JKS));
			ks.load(in, userBPass.toCharArray());

			if (ks.isKeyEntry(userBAlias)) {
				X509Certificate cert = (X509Certificate) ks.getCertificate(userAAlias);
				return cert;
			} else
				return null;

		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
}
