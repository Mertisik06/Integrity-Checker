import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Files {
	
	String path;
	String hashValue;
	
	public void HashWords(String path,int hashMode) throws FileNotFoundException, NoSuchAlgorithmException {
		Scanner scanner = new Scanner(new File(path));
		MessageDigest m = null;
		String words="";
		while (scanner.hasNextLine()) {
			String line = scanner.nextLine();
			words+=line;
			
		}
		
		// choose Hash Algorithm
		// MD5
		if(hashMode == 0) {
			 m = MessageDigest.getInstance("MD5");
			 m.reset();
			 m.update(words.getBytes());
			 byte[] digest = m.digest();
			 BigInteger bigInt = new BigInteger(1,digest);
			 String hashtext = bigInt.toString(16);
			 // Now we need to zero pad it if you actually want the full 32 chars.
			 while(hashtext.length() < 32 ){
			   hashtext = "0"+hashtext;
			 }
			 this.hashValue=hashtext;
			 
		}
		// SHA-256
		else if(hashMode == 1) {
			 m = MessageDigest.getInstance("SHA-256");
		     byte[] bytSHA = m.digest(words.getBytes());
		     BigInteger intNumber = new BigInteger(1, bytSHA);
		     String strHashCode = intNumber.toString(16);
		        while (strHashCode.length() < 64) {
		            strHashCode = "0" + strHashCode;
		        }
		     this.hashValue = strHashCode;
		}
		
	}
	
	public String getHashValue() {
		return hashValue;
	}
	public Files(String path) {
		this.path=path;
		
	}
	
}
