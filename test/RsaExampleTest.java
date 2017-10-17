import com.sun.org.apache.xml.internal.security.signature.InvalidSignatureValueException;
import junit.framework.TestCase;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

/**
 * Created by jbackes on 5/6/17
 */
public class RsaExampleTest extends TestCase {
  private RsaExample _example;
  private String _message;

  @Override
  public void setUp() throws Exception {
    _example = new RsaExample();
    _message = "Now is the time for all good men and women to come to the aid of their country.";
  }

  public void testGenerateKey()  throws NoSuchAlgorithmException {
    Key key = _example.generateKey();

    assertEquals(key.getAlgorithm(), "AES");
    assertEquals(key.getFormat(), "RAW");

    System.out.println(Arrays.toString(key.getEncoded()));
  }

  public void testGetKeyPairFromKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
    KeyPair pair = _example.getKeyPairFromKeyStore();

    assertNotNull(pair);
    assertNotNull(pair.getPublic());
    assertNotNull(pair.getPrivate());
    assertEquals(pair.getPublic().getAlgorithm(), "RSA");
    assertNotNull(Arrays.toString(pair.getPublic().getEncoded()));
    assertEquals(pair.getPublic().getFormat(),"X.509");

    System.out.println(Arrays.toString(pair.getPrivate().getEncoded()));
    System.out.println(Arrays.toString(pair.getPublic().getEncoded()));
  }

  public void testEncryptionDecryption()
      throws KeyStoreException
      , CertificateException
      , NoSuchAlgorithmException
      , IOException
      , UnrecoverableEntryException
      , NoSuchPaddingException
      , InvalidKeyException
      , BadPaddingException
      , IllegalBlockSizeException
  {
    KeyPair pair = _example.getKeyPairFromKeyStore();

    assertNotNull(pair);
    assertNotNull(pair.getPublic());
    assertNotNull(pair.getPrivate());

    String cipherText = _example.encrypt(_message, pair.getPublic());

    assertNotNull(cipherText);
    assertEquals( _example.decrypt(cipherText, pair.getPrivate()), _message);
  }

  public void testSignVerify()
      throws KeyStoreException
      , CertificateException
      , NoSuchAlgorithmException
      , IOException
      , UnrecoverableEntryException
      , InvalidKeyException
      , SignatureException
  {
    String plainText = "Please sign me.";
    KeyPair pair = _example.getKeyPairFromKeyStore();

    assertNotNull(pair);
    assertNotNull(pair.getPublic());
    assertNotNull(pair.getPrivate());

    String signature = _example.sign(plainText, pair.getPrivate());
    assertNotNull(signature);

    assertTrue(_example.verify(plainText, signature, pair.getPublic()));

    plainText += ".";
    assertFalse(_example.verify(plainText, signature, pair.getPublic()));
  }
}