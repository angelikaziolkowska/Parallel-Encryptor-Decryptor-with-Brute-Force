import java.security.Key;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.crypto.spec.PBEParameterSpec;
import java.nio.charset.StandardCharsets;

// check all kinds of results, seperately save for different iteration counts
// save results, not just print 
// but also altogether check medium, lower and upper bounds - use big O notation
// produce pretty graphs of results, if with code then that's even better
// check for analysis classes in java
// understand/check JCA methods. how it all works, if i can make this algorithm async/recursive

public class BruteForceWithIteration {
    static String[] passwords = { "a%gBc" };
    static int count = 850;
    public static int password_max_length = 5;
    static long[][] experiments = new long[passwords.length][3];
    static Cipher pbeCipher_en;
    static Cipher pbeCipher_de;
    static long[] avarage_en_time = new long[passwords.length];
    static long[] avarage_de_time = new long[passwords.length];
    static long[] avarage_key_gen_time = new long[passwords.length];
    static long start_time;
    static byte[] cleartext = "This is another example".getBytes();
    static String decryptedtext;

    public static void main(String[] args) throws Exception {
        // initialise
        PBEKeySpec pbeKeySpec;
        PBEParameterSpec pbeParamSpec;
        SecretKeyFactory keyFac;

        for (int i = 0; i < passwords.length; i++) {
            byte[] salt = { (byte) 0xc7, (byte) 0x73, (byte) 0x21, (byte) 0x8c, (byte) 0x7e, (byte) 0xc8, (byte) 0xee,
                    (byte) 0x99 };

            pbeParamSpec = new PBEParameterSpec(salt, count);

            pbeKeySpec = new PBEKeySpec(passwords[i].toCharArray());

            keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

            experiments[i][0] = i; // the password
            experiments[i][1] = count; // the count

            Key pbeKey = GenerateKey(pbeKeySpec, keyFac, i, count);

            // encrypt the plaintext
            // start_time = System.nanoTime();
            byte[] ciphertext = Encrypt(pbeParamSpec, pbeKey);

            // decrypt the ciphertext without Password
            start_time = System.nanoTime();
            Decrypt(salt, count, ciphertext);
            experiments[i][2] = System.nanoTime() - start_time;
        }
    }

    public static void Decrypt(byte[] salt, int count, byte[] ciphertext) throws NoSuchAlgorithmException {
        int cores = Runtime.getRuntime().availableProcessors();
        int lengthSet = password_max_length / cores;
        int end = 0;
        ExecutorService executorService = Executors.newFixedThreadPool(cores);

        while (end < password_max_length) {
            int start = end + 1;
            end = start + lengthSet;

            if (end > password_max_length)
                end = password_max_length;

            executorService.submit(new BFSWithIterationCracker(start, end, salt, count, ciphertext));
        }
        executorService.shutdown();
    }

    private static Key GenerateKey(PBEKeySpec pbeKeySpec, SecretKeyFactory keyFac, int i, int count)
            throws InvalidKeySpecException {
        Key pbeKey = keyFac.generateSecret(pbeKeySpec);
        return pbeKey;
    }

    public static byte[] Encrypt(PBEParameterSpec pbeParamSpec, Key pbeKey) throws Exception {
        pbeCipher_en = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher_en.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
        return pbeCipher_en.doFinal(cleartext);
    }
}
