package app;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.api.services.gmail.Gmail;

import keystore.KeyStoreReader;
import mailclient.MailBody;
import support.MailHelper;
import support.MailWritter;
import util.GzipUtil;
import util.IVHelper;
import util.Base64;

public class WriteMailClient extends MailClient {

	/*
	 * private static final String KEY_FILE = "./data/session.key"; private static
	 * final String IV1_FILE = "./data/iv1.bin"; private static final String
	 * IV2_FILE = "./data/iv2.bin"; private static short BLOCK_SIZE = 16;
	 */
	private static final String USER_A_JKS = "./data/usera.jks";
	private static final String USER_B_JKS = "./data/userb.jks";
	private static final String userBAlias = "userb";
	private static final String userAAlias = "usera";
	private static final String userBPass = "b";
	private static final String userAPass = "a";

	/*
	 * // kreiranje kljuca private static SecretKey generateKey() { try { //
	 * generator para kljuceva za AES algoritam KeyGenerator keyGen =
	 * KeyGenerator.getInstance("AES"); // generise kljuc za AES, defaultne velicine
	 * od 128 bita SecretKey secretKey = keyGen.generateKey(); return secretKey;
	 * 
	 * } catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
	 * 
	 * return null; }
	 */
	static {
		// staticka inicijalizacija
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
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
			
			//kreiranje xml dokumenta
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
			
			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("mail");
			
			Element mailSubject = doc.createElement("mailSubject");
			Element mailBody = doc.createElement("mailBody");

			mailSubject.setTextContent(subject);
			mailBody.setTextContent(text);
			rootElement.appendChild(mailSubject);
			rootElement.appendChild(mailBody);
			doc.appendChild(rootElement);
			
			
			//dokument pre enkripcije
			String xml = xmlAsString(doc);
			System.out.println("Mail pre enkripcije: " + xml);
			
			// generisanje tajnog (session) kljuca
			SecretKey secretKey = generateKey();
			
			
			// citanje keystore-a kako bi se izvukao sertifikat primaoca
			// i kako bi se dobio njegov javni kljuc
			PublicKey publicKey = getPublicKey();
			
			// cipher za kriptovanje XML-a
			XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
			// inicijalizacija za kriptovanje
			xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
			
			// cipher za kriptovanje tajnog kljuca
			// koristi se javni RSA kljuc za kriptovanje
			XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
			// inicijalizacija za kriptovanje tajnog kljuca javnim kljucem
			keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
			
			// kreireanje EncryptedKey objekta koji sadrzi enkriptovani tajni kljuc
			EncryptedKey encryptedKey = keyCipher.encryptKey(doc, secretKey);
			System.out.println("Kriptovan tajni kljuc: " + encryptedKey);
			
			// kreiranje EncryptedData objekta
			// ovaj element je koreni element XMl enkripcije
			EncryptedData encryptedData = xmlCipher.getEncryptedData();
										//sifruje se sam dokument kao takav
			
			// kreiranje KeyInfo objekta, podaci o samom kljucu
			KeyInfo keyInfo = new KeyInfo(doc);
			
			// postavljamo naziv
			keyInfo.addKeyName("Kriptovani tajni kljuc");

			// postavljamo kriptovani kljuc, vrednost kljuca
			keyInfo.add(encryptedKey);

			// postavljanje KeyInfo za element koji se kriptuje
			encryptedData.setKeyInfo(keyInfo);
			
			// potpisivanje dokumenta
			WriteMailClient sign = new WriteMailClient();
			sign.signingDocument(doc);
			
			
			//kriptovati sadrzaj dokumenta
			xmlCipher.doFinal(doc, rootElement, true);
			
			//slanje poruke
			String encryptedXml = xmlAsString(doc);
			System.out.println("Mail posle enkripcije: " + encryptedXml);
			
			String cipherSubject = cipherData(secretKey, subject);
			
			MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, cipherSubject, encryptedXml);
			MailWritter.sendMessage(service, "me", mimeMessage);
			
			/*
			 * // TODO: Compress and encrypt the content before sending.
			 * 
			 * // compress String compressedSubject =
			 * Base64.encodeToString(GzipUtil.compress(subject)); String compressedText =
			 * Base64.encodeToString(GzipUtil.compress(text));
			 * 
			 * // generate Key SecretKey secretKey = generateKey();
			 * 
			 * String encodedKey = Base64.encodeToString(secretKey.getEncoded());
			 * 
			 * // javni kljuc korisnika B PublicKey publicKey = getPublicKey();
			 * 
			 * // klasa za sifrovanje Cipher aesCipherEnc =
			 * Cipher.getInstance("AES/CBC/PKCS5Padding");
			 * 
			 * // inicijalizacija za sifrovanje IvParameterSpec ivParameterSpec1 =
			 * IVHelper.createIV(); aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey,
			 * ivParameterSpec1);
			 * 
			 * // sifrovanje byte[] ciphertext =
			 * aesCipherEnc.doFinal(compressedText.getBytes()); String ciphertextStr =
			 * Base64.encodeToString(ciphertext); System.out.println("Kriptovan tekst: " +
			 * ciphertextStr);
			 * 
			 * // inicijalizacija za sifrovanje IvParameterSpec ivParameterSpec2 =
			 * IVHelper.createIV(); aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey,
			 * ivParameterSpec2);
			 * 
			 * // sifrovanje byte[] ciphersubject =
			 * aesCipherEnc.doFinal(compressedSubject.getBytes()); String ciphersubjectStr =
			 * Base64.encodeToString(ciphersubject);
			 * System.out.println("Kriptovan subject: " + ciphersubjectStr);
			 * 
			 * // enkripcija privatnog kljuca javnim kljucem String encryptedAESKeyString =
			 * encryptAESKey(encodedKey, publicKey);
			 * 
			 * // String message = ciphersubjectStr + ciphertextStr;
			 * 
			 * MailBody mailBody = new MailBody(ciphertextStr,
			 * Base64.encodeToString(ivParameterSpec1.getIV()),
			 * Base64.encodeToString(ivParameterSpec2.getIV()), encryptedAESKeyString);
			 * String mailBody1 = mailBody.toCSV();
			 * 
			 * 
			 * // snimanje kljuca i IV JavaUtils.writeBytesToFilename(KEY_FILE,
			 * secretKey.getEncoded()); JavaUtils.writeBytesToFilename(IV1_FILE,
			 * ivParameterSpec1.getIV()); JavaUtils.writeBytesToFilename(IV2_FILE,
			 * ivParameterSpec2.getIV());
			 * 
			 * 
			 * MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever,
			 * ciphersubjectStr, mailBody1); MailWritter.sendMessage(service, "me",
			 * mimeMessage);
			 */

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	// Iz usera.jks preuzeti sertifikat i javni ključ korisnika B
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
	
	//transformacija dokumenta u xml fajl kao string
		private static String xmlAsString(Document doc) throws TransformerException {
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			String output = writer.getBuffer().toString().replaceAll("\n|\r", "");

			return output;
		}
		
		// kreiranje tajnog (session) kljuca
		private static SecretKey generateKey() {
			try {

				KeyGenerator keyGen = KeyGenerator.getInstance("DESede");

				return keyGen.generateKey();

			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}

			return null;
		}

		private static String cipherData(SecretKey secretKey, String data) {
			try {
				String compressedData = Base64.encodeToString(GzipUtil.compress(data));
				Cipher desCipherDec = Cipher.getInstance("DESede/CBC/PKCS5Padding");

				// inicijalizacija za sifrovanje
				IvParameterSpec ivParameterSpec2 = new IvParameterSpec(new byte[8]);
				desCipherDec.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);

				byte[] cipherData = desCipherDec.doFinal(compressedData.getBytes());
				String cipherDataStr = Base64.encodeToString(cipherData);
				System.out.println("Kriptovan text: " + cipherDataStr);

				return cipherDataStr;

			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return null;
		}
		
		private static PrivateKey getPrivateKey() {
			try {
				KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
				// ucitavanje keyStore
				BufferedInputStream in = new BufferedInputStream(new FileInputStream(USER_A_JKS));
				keyStore.load(in, userAPass.toCharArray());

				if (keyStore.isKeyEntry(userAAlias)) {
					PrivateKey privateKey = (PrivateKey) keyStore.getKey(userAAlias, userAPass.toCharArray());
					return privateKey;
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
			} catch (UnrecoverableKeyException e) {
				e.printStackTrace();
				return null;
			}
		}

		private void signingDocument(Document doc) {
			PrivateKey privateKey = getPrivateKey();
			Certificate cert = getCertificate();
			System.out.println("Signing....");
			doc = signDocument(doc, privateKey, cert);
		}
		
		private Document signDocument(Document doc, PrivateKey privateKey, Certificate cert) {
			try {
				Element rootEl = doc.getDocumentElement();

				// kreira se signature objekat
				XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
				// kreiraju se transformacije nad dokumentom
				Transforms transforms = new Transforms(doc);

				// iz potpisa uklanja Signature element
				// Ovo je potrebno za enveloped tip po specifikaciji
				transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
				// normalizacija, canonicalization (C14N)
				transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);

				// potpisuje se citav dokument (URI "")
				sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

				// U KeyInfo se postavalja Javni kljuc samostalno i citav sertifikat
				sig.addKeyInfo(cert.getPublicKey());
				sig.addKeyInfo((X509Certificate) cert);
				System.out.println("sign: " + sig);
				System.out.println("sig.keyinfo " + sig.getKeyInfo());

				// poptis je child root elementa
				rootEl.appendChild(sig.getElement());
				System.out.println("sign pre kriptovanja: " + sig);

				System.out.println("sign signature: " + sig.getSignatureValue());
				// potpisivanje
				sig.sign(privateKey);
				System.out.println("sign kriptovani: " + sig);

				return doc;
			} catch (TransformationException e) {
				e.printStackTrace();
				return null;
			}  catch (DOMException e) {
				e.printStackTrace();
				return null;
			} catch (XMLSecurityException e) {
				e.printStackTrace();
				return null;
			}
		}

		private Certificate getCertificate() {
			try {
				// kreiramo instancu KeyStore
				KeyStore ks = KeyStore.getInstance("JKS", "SUN");
				// ucitavamo podatke
				BufferedInputStream in = new BufferedInputStream(new FileInputStream(USER_B_JKS));
				ks.load(in, userBPass.toCharArray());

				if (ks.isKeyEntry(userBAlias)) {
					Certificate cert = (Certificate) ks.getCertificate(userAAlias);
				//	System.out.println("cert " + cert.getSignature());
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
