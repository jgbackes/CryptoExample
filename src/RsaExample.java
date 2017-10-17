import javax.crypto.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Example for Java Crypto API
 */
public class RsaExample {

  /**
   * Static method to get a pseudo random key
   *
   * @return a pseudo random AES key
   * @throws NoSuchAlgorithmException
   */
  public Key generateKey() throws NoSuchAlgorithmException {
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(new SecureRandom());

    return generator.generateKey();
  }

  /**
   * Static method to get a pseudo random 2048bit RSA keypair
   *
   * @return a pseudo random 2048bit RSA keypair, or null if public or private are not available
   * @throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException
   */
  public KeyPair getKeyPairFromKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
    //Generated with:
    //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks

    PublicKey publicKey = null;
    PrivateKey privateKey = null;
    KeyPair result = null;

    InputStream ins = RsaExample.class.getResourceAsStream("/keystore.jks");

    if (ins != null) {
      KeyStore keyStore = KeyStore.getInstance("JCEKS");
      keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password
      KeyStore.PasswordProtection keyPassword =       //Key password
          new KeyStore.PasswordProtection("s3cr3t".toCharArray());

      KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

      java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
       publicKey = cert.getPublicKey();
       privateKey = privateKeyEntry.getPrivateKey();
    }

    if (publicKey != null && privateKey != null) {
      result = new KeyPair(publicKey, privateKey);
    }

    return result;
  }

  /**
   * @param plainText The text to be encrypted
   * @param publicKey The public key of the KeyPair
   * @return Encrypted text
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   */
  public String encrypt(String plainText, PublicKey publicKey) throws NoSuchPaddingException
      , NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    Cipher encryptCipher = Cipher.getInstance("RSA");
    encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

    byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

    return Base64.getEncoder().encodeToString(cipherText);
  }

  /**
   * @param cipherText The encrypted text
   * @param privateKey The private key of the keyPair
   * @return The plain text
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   */
  public String decrypt(String cipherText, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    byte[] bytes = Base64.getDecoder().decode(cipherText);

    Cipher decriptCipher = Cipher.getInstance("RSA");
    decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

    return new String(decriptCipher.doFinal(bytes), UTF_8);
  }

  /**
   * @param plainText  The text from which we want a digital signature
   * @param privateKey The private key from the keyPair
   * @return A string in base64 that represents the signature
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   * @throws SignatureException
   */
  public String sign(String plainText, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature privateSignature = Signature.getInstance("SHA256withRSA");
    privateSignature.initSign(privateKey);
    privateSignature.update(plainText.getBytes(UTF_8));

    byte[] signature = privateSignature.sign();

    return Base64.getEncoder().encodeToString(signature);
  }

  /**
   * This method is used to verify that the plainText has not changed
   * since the plainText was signed with the private half of the keypair
   *
   * @param plainText The text to sign
   * @param signature The digital signature for this plainText
   * @param publicKey The public key half of the keyPair
   * @return boolean TRUE if signature matches
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   * @throws SignatureException
   */
  public boolean verify(String plainText, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature publicSignature = Signature.getInstance("SHA256withRSA");
    publicSignature.initVerify(publicKey);
    publicSignature.update(plainText.getBytes(UTF_8));

    byte[] signatureBytes = Base64.getDecoder().decode(signature);

    return publicSignature.verify(signatureBytes);
  }
}