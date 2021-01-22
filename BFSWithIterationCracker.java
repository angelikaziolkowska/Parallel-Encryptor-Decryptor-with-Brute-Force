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

public class BFSWithIterationCracker implements Runnable {
    public static char[] ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"£$%^&*()-_=+[{]};:'@#~,<.>/?'"
            .toCharArray();
    static Cipher pbeCipher_de;
    private int start;
    private int end;
    // private final MessageDigest digest = MessageDigest.getInstance("MD5");
    private static boolean DONE = false;
    static String found;
    static byte[] ciphertext;
    PBEKeySpec pbeKeySpec;
    SecretKeyFactory keyFac;
    static byte[] salt;
    static int count;
    byte[] clearmessage;

    public BFSWithIterationCracker(int s, int e, byte[] sal, int cou, byte[] ciph) throws NoSuchAlgorithmException {
        start = s;
        end = e;
        salt = sal;
        count = cou;
        ciphertext = ciph;
    }

    public void generate(StringBuilder sb, int n) {
        if (DONE)
            return;

        if (n == sb.length()) {

            String password = sb.toString();
            System.out.println(password);
            // MD5 our password
            // byte[] bytes = digest.digest(password.getBytes());

            try {
                PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);
                Key pbeKey = GenerateKey(password);
                byte[] clear = Decrypt(pbeParamSpec, pbeKey);
                clearmessage = clear;
            } catch (Exception e) {
            }

            if (password.equals(BruteForceWithIteration.passwords[0])) {
                found = password;
                DONE = true;
                return;
            }
            return;
        }
        for (int i = 0; i < ALPHABET.length && !DONE; i++) {
            char letter = ALPHABET[i];
            sb.setCharAt(n, letter);
            generate(sb, n + 1);
        }
    }

    public Key GenerateKey(String password) throws Exception {
        pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, count, 16);
        keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        return keyFac.generateSecret(pbeKeySpec);
    }

    public static byte[] Decrypt(PBEParameterSpec pbeParamSpec, Key pbeKey) throws Exception {
        pbeCipher_de = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher_de.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);

        return pbeCipher_de.doFinal(ciphertext);
    }

    @Override
    public void run() {

        for (int length = start; length <= end && !DONE; length++) {
            StringBuilder sb = new StringBuilder();
            sb.setLength(length);
            generate(sb, 0);
        }

        if (DONE) {
            long duration = System.nanoTime() - BruteForceWithIteration.start_time;
            System.out.println("Password cracked in " + TimeUnit.SECONDS.convert(duration, TimeUnit.NANOSECONDS)
                    + " s. Password was = " + found);
            System.out.println("Clear message is: ");
            // for (int i = 0; i < clearmessage.length; i++) {
            // System.out.print(" " + clearmessage[i]);
            // }
            // System.out.println("\n ");
            String mess = Utils.toHex(clearmessage);
            // String mess = Utils.toHex(clearmessage).toString();
            System.out.print(mess);

        } else {
            System.out.println("Password not cracked for subset [" + start + ", " + end + "]");
        }
    }
}