import javax.crypto.Cipher;
import java.security.MessageDigest;
import org.bouncycastle.crypto.engines.AESEngine;

public class Example {
    // RSA-4096 legacy chain, target SLH-DSA.
    static final String LEGACY = "RSA-4096";
    static final String TARGET = "SLH-DSA";
    static final String HASH = "SHA-512";
}
