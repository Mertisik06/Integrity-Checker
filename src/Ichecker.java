import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;

public class Ichecker {

	public static void main(String[] args) throws Exception {
		SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
		Date date = new Date();

		if (args[0].equals("createCert")) {
			CertAndKeyGen certAndKeyGen = new CertAndKeyGen("RSA", "MD5WithRSA", null);
			certAndKeyGen.generate(2048);
			Date cert_date = new GregorianCalendar(2020, Calendar.JANUARY, 1).getTime();

			X509Certificate cert = certAndKeyGen.getSelfCertificate(new X500Name("CN=Group"), cert_date, (long)60*60*24*365*10);
			PrintStream publicCertFile = new PrintStream(args[4]);

			BASE64Encoder encoder = new BASE64Encoder();
			publicCertFile.println(X509Factory.BEGIN_CERT);
			encoder.encodeBuffer(cert.getEncoded(), publicCertFile);
			publicCertFile.println(X509Factory.END_CERT);

			PrintStream publicKeyFile = new PrintStream("public.pem");
			PublicKey publicKey = certAndKeyGen.getPublicKey();
			encoder.encodeBuffer(publicKey.getEncoded(), publicKeyFile);

			PrintStream privateKeyFile = new PrintStream(args[2]);
			PrivateKey privateKey = certAndKeyGen.getPrivateKey();

			byte[] encodedBytesPrivate = (Arrays.toString(privateKey.getEncoded()) + "This is the private key file").getBytes();

			String password;
			Scanner sc= new Scanner(System.in);
			System.out.print("Password: ");
			password= sc.nextLine();

			byte[] hashedPassword = hashing(password);
			byte[] finalPrivateKey = Base64.getEncoder().encode(encryption(encodedBytesPrivate, hashedPassword));

			privateKeyFile.write(finalPrivateKey);
		}

		if(args[0].equals("createReg")){
			String password_2;
			Scanner sc_2= new Scanner(System.in);
			System.out.print("Password: ");
			password_2= sc_2.nextLine();
			byte[] hashedPassword_2 = hashing(password_2);
			String d="";
			try {
				File myObj = new File(args[10]);
				Scanner myReader = new Scanner(myObj);
				while (myReader.hasNextLine()) {

					byte[] data = myReader.nextLine().getBytes();
					byte[] decryptedData= decryption(Base64.getDecoder().decode(data), hashedPassword_2);
					d = new String(decryptedData, StandardCharsets.UTF_8);
				}
				myReader.close();
			} catch (Exception e) {
				FileOutputStream logOut1 = new FileOutputStream(args[6]);
				logOut1.write((formatter.format(date)+": Wrong password attempt! ").getBytes());
				logOut1.write(System.getProperty("line.separator").getBytes());
				logOut1.close();
				System.exit(0);
				//e.printStackTrace();
			}

			BufferedWriter logOut = new BufferedWriter(	new FileWriter(args[6], true));
			String lastWord = d.substring(d.lastIndexOf(" ")+1);
			if(lastWord.equals("file")){
				d="True";
				//System.out.println("True password");
			}
			ArrayList<String> allFiles=new ArrayList<String>();
			ArrayList<Files> allFileObjs=new ArrayList<Files>();
			byte[] s;
			int ctrlPoint ;
			String allWords="";
			Scanner scanner = new Scanner(new File(args[10]));
			KeyPair keyPair = buildKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();

			if(args[8].equals("MD5")) {
				ctrlPoint = 0;
			}
			else {
				ctrlPoint = 1;
			}
			ReadFile(args[4],allFiles);

			for(String a:allFiles) {
				Files nextFile=new Files(a);
				nextFile.HashWords(a,ctrlPoint);
				allFileObjs.add(nextFile);

			}
			String RegistrElements = "";
			File f = new File(args[4]);

			FileOutputStream registerOut = new FileOutputStream(args[2]);
			String pathreg=f.getAbsolutePath();

			int count = 0 ;
			for(Files wordsinFile:allFileObjs) {
				logOut.write((formatter.format(date)+": "+wordsinFile.path + " is added to registry"));
				logOut.write(System.getProperty("line.separator"));
				registerOut.write((wordsinFile.path + " " + wordsinFile.getHashValue()).getBytes());
				registerOut.write(System.getProperty("line.separator").getBytes());
				count++;
			}
			logOut.write((formatter.format(date)+": "+count + " files are added to the registry and registry creation is finished."));
			logOut.write(System.getProperty("line.separator"));
			Files registerHasValue=new Files(args[4]);
			registerHasValue.HashWords(args[2], ctrlPoint);
			registerOut.write("Signature->".getBytes());
			byte[] signature=encrypt(privateKey, registerHasValue.hashValue);
			byte[] signBytes = Base64.getEncoder().encode(signature);
			registerOut.write(signBytes);
			registerOut.close();
			logOut.close();

		}

		else if(args[0].equals("check")){
			ArrayList<String> allFiles=new ArrayList<String>();
			ArrayList<Files> allFileObjs=new ArrayList<Files>();
			ArrayList<String> files = new ArrayList<String>();
			BufferedReader regScanner = new BufferedReader(new FileReader(args[2]));
			String [] fileinfo = new String[20] ;
			int i=0;
			int ctrlPoint ;
			if(args[8].equals("MD5")) {
				ctrlPoint = 0;
			}
			else {
				ctrlPoint = 1;
			}
			String curLine="";
			BufferedWriter logOut = new BufferedWriter(	new FileWriter(args[6], true));
			while((curLine = regScanner.readLine()) != null) {
				if (!curLine.substring(0, 9).equals("Signature")) {
					String[] splitted = curLine.split(" ");
					files.add(splitted[0].trim());
					fileinfo[i] = splitted[0].trim();
					fileinfo[i + 1] = splitted[1].trim();
					i = i + 2;
				}
			}
			regScanner.close();

			ReadFile(args[4],allFiles);

			for(String a:allFiles) {
				Files nextFile=new Files(a);
				nextFile.HashWords(a,ctrlPoint);
				allFileObjs.add(nextFile);
			}
			boolean change = false;
			boolean filechange = false;
			for(Files wordsinFile:allFileObjs) {
				int count = 0;
				for(int x = 0 ; x<(fileinfo.length);){
					if(wordsinFile.path.equals(fileinfo[x])) {
						if (wordsinFile.getHashValue().equals(fileinfo[x+1])) {
							change = false;
							filechange=false;
							break;
						}
						else {
							logOut.write((formatter.format(date) + ": " + wordsinFile.path + " file altered"));
							logOut.write(System.getProperty("line.separator"));
							change = true;
							filechange=false;
							break;
						}
					}
					else{
						change = true;
						filechange=true;
					}
					x=x+2;
				}
				if(filechange){
					logOut.write((formatter.format(date) + ": " + wordsinFile.path + " file created"));
					logOut.write(System.getProperty("line.separator"));
				}
			}
			boolean isdeleted = false;
			for(String namef:files){
				for(Files wordsinFile:allFileObjs){
					if(namef.equals(wordsinFile.path)){
						isdeleted=false;
						break;
					}
					else{
						isdeleted=true;
					}
				}
				if(isdeleted){
					change=true;
					logOut.write((formatter.format(date) + ": " + namef + " file deleted"));
					logOut.write(System.getProperty("line.separator"));
				}
			}
			if(!change){
				logOut.write((formatter.format(date) + ": The directory is checked and no change is detected!"));
				logOut.write(System.getProperty("line.separator"));
			}
			logOut.close();
		}
	}
	public static byte[] encryption(byte[] messageBytes, byte[]key) {
		byte[] encrypted_message = null;
		try {
			SecretKey sKey = new SecretKeySpec(key, "AES");
			Cipher encrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
			encrypt.init(Cipher.ENCRYPT_MODE, sKey);
			encrypted_message = encrypt.doFinal(messageBytes);
			return encrypt.doFinal(messageBytes);
		} catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return encrypted_message;
	}

	public static byte[] decryption(byte[] encryptedMessage, byte[] key) {
		byte[] decrypted_message = null;
		try {
			SecretKey sKey = new SecretKeySpec(key,"AES");
			Cipher decrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
			decrypt.init(Cipher.DECRYPT_MODE, sKey);
			decrypted_message = decrypt.doFinal(encryptedMessage);
			return decrypt.doFinal(encryptedMessage);
		} catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException exception) {
			exception.printStackTrace();
		}
		return decrypted_message;
	}

	public static byte[] hashing (String input) {
		try {

			String binary = new BigInteger(input.getBytes()).toString(2);
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] messageDigest = md.digest(binary.getBytes());
			return messageDigest;
		}

		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

	}
	public static ArrayList<String> ReadFile(String arg,ArrayList<String> aFile) {
		File root = new File( arg );

		File[] list = root.listFiles();
		if (list == null) return null;
		for ( File f : list ) {
			if ( f.isDirectory() ) {
				ReadFile( f.getAbsolutePath(),aFile );
			}
			else {
				aFile.add(f.getAbsolutePath());
			}
		}
		return null;

	}

	public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
		final int keySize = 2048;
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keySize);
		return keyPairGenerator.genKeyPair();
	}

	public static byte[] encrypt(Key privateKey, String message) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(message.getBytes());
	}

	public static byte[] decrypt(Key publicKey, byte [] encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(encrypted);
	}

	public static PrivateKey getPrivateKey(String key) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(key);
		PKCS8EncodedKeySpec keySpec = new  PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
	}
	public static PublicKey getPublicKey(String key) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(key);
		X509EncodedKeySpec keySpec = new  X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publickey = keyFactory.generatePublic(keySpec);
		return publickey;
	}

}
