package rsa;

import java.util.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Encrypt{
    @SuppressWarnings("resource")
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
    IllegalBlockSizeException, BadPaddingException {
    	 Scanner s = new Scanner(System.in);
      //Import and Initialize To generate an RSA key pair, use the getInstance() static method of the KeyPairGenerator class and pass the RSA parameter as the encryption algorithm to be used.
    	KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance("RSA");
    	//Make an object SecureRandom object
        SecureRandom secureRandom = new SecureRandom();
        
        //initialize method (keyPair and secureRandom)
        keyPairGenerator.initialize(2048,secureRandom);
        
        //The generateKeyPair() method will generate a new KeyPair every time it is called.
        KeyPair pair = keyPairGenerator.generateKeyPair();
        
        //we can use the getPublic() and getPrivate() methods of the KeyPair class to retrieve the public key and private key respectively.

        //To see the generated keys call getEncoded() on each of the methods, which return the key in its primary encoding format or null if the key does not support encoding.
        //Convert keys to string with encodeToString method of Base64.Encoder 
        PublicKey publicKey = pair.getPublic();
        String publicKeyString =
                Base64.getEncoder().encodeToString(publicKey.getEncoded());

        System.out.println("public key = "+ publicKeyString);

        PrivateKey privateKey = pair.getPrivate();
        String privateKeyString =
                Base64.getEncoder().encodeToString(privateKey.getEncoded());

        System.out.println("private key = "+ privateKeyString);
        //Encrypts Message
        //Create Cipher Obj using getInstance() (static method) 
        Cipher encryptionCipher = Cipher.getInstance("RSA");
        
        //The Cipher's init() method initializes the cipher with a key for encryption, decryption, key wrapping, or key unwrapping depending on the value of opmode.
        encryptionCipher.init(Cipher.ENCRYPT_MODE,privateKey);
        System.out.println("Enter Message to be Encrypted:");
        String message = s.nextLine();
        byte[] encryptedMessage =
        //The doFinal() method performs the encryption operation depending on how the cipher was initialized and resets once it finishes allowing encrypting more data.
        encryptionCipher.doFinal(message.getBytes());
        String encryption =
        Base64.getEncoder().encodeToString(encryptedMessage);
        System.out.println("encrypted message = "+encryption);
 
        //Decrypts Message
        Cipher decryptionCipher = Cipher.getInstance("RSA");
        decryptionCipher.init(Cipher.DECRYPT_MODE,publicKey);
        byte[] decryptedMessage =
        decryptionCipher.doFinal(encryptedMessage);
        String decryption = new String(decryptedMessage);
        System.out.println("decrypted message = "+decryption);
 
    }

}