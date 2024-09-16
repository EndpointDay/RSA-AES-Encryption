import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static String encryptAES(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decryptAES(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedData);
    }

    public static String encryptRSA(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decryptRSA(String encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedData);
    }

    public static void exportAESKey(SecretKey secretKey, String fileName) throws IOException {
        byte[] encodedKey = secretKey.getEncoded();
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(encodedKey);
        fos.close();
        System.out.println("AES Key exported to " + fileName);
    }

    public static SecretKey importAESKey(String fileName) throws IOException {
        byte[] encodedKey = new byte[16];
        FileInputStream fis = new FileInputStream(fileName);
        fis.read(encodedKey);
        fis.close();
        return new SecretKeySpec(encodedKey, "AES");
    }

    public static void exportRSAKey(Key key, String fileName) throws IOException {
        byte[] encodedKey = key.getEncoded();
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(encodedKey);
        fos.close();
        System.out.println("RSA Key exported to " + fileName);
    }

    public static PublicKey importRSAPublicKey(String fileName) throws Exception {
        byte[] encodedKey = new byte[294];
        FileInputStream fis = new FileInputStream(fileName);
        fis.read(encodedKey);
        fis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
    }

    public static PrivateKey importRSAPrivateKey(String fileName) throws Exception {
        byte[] encodedKey = new byte[2048 / 8];
        FileInputStream fis = new FileInputStream(fileName);
        fis.read(encodedKey);
        fis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
    }

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        SecretKey aesKey = null;
        System.out.println("### AES Key Setup ###");
        System.out.print("Do you want to (1) Generate a new AES key or (2) Load an existing AES key? ");
        String aesChoice = scanner.nextLine();
        if (aesChoice.equals("1")) {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            aesKey = keyGen.generateKey();
            System.out.println("New AES key generated.");
        } else if (aesChoice.equals("2")) {
            System.out.print("Enter the filename to load the AES key: ");
            aesKey = importAESKey(scanner.nextLine());
            System.out.println("AES key loaded from file.");
        }

        System.out.print("Enter text to encrypt with AES: ");
        String aesData = scanner.nextLine();
        String aesEncrypted = encryptAES(aesData, aesKey);
        String aesDecrypted = decryptAES(aesEncrypted, aesKey);

        System.out.println("\nAES Encrypted: " + aesEncrypted);
        System.out.println("AES Decrypted: " + aesDecrypted);

        System.out.print("Do you want to export the AES key? (yes/no): ");
        if (scanner.nextLine().equalsIgnoreCase("yes")) {
            System.out.print("Enter filename to save the AES key: ");
            assert aesKey != null;
            exportAESKey(aesKey, scanner.nextLine());
        }

        PublicKey rsaPublicKey = null;
        PrivateKey rsaPrivateKey = null;
        System.out.println("\n### RSA Key Setup ###");
        System.out.print("Do you want to (1) Generate new RSA keys or (2) Load existing RSA keys? ");
        String rsaChoice = scanner.nextLine();
        if (rsaChoice.equals("1")) {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair rsaKeyPair = keyPairGen.generateKeyPair();
            rsaPublicKey = rsaKeyPair.getPublic();
            rsaPrivateKey = rsaKeyPair.getPrivate();
            System.out.println("New RSA key pair generated.");
        } else if (rsaChoice.equals("2")) {
            System.out.print("Enter the filename to load the RSA public key: ");
            rsaPublicKey = importRSAPublicKey(scanner.nextLine());
            System.out.print("Enter the filename to load the RSA private key: ");
            rsaPrivateKey = importRSAPrivateKey(scanner.nextLine());
            System.out.println("RSA keys loaded from files.");
        }

        System.out.print("Enter text to encrypt with RSA: ");
        String rsaData = scanner.nextLine();
        String rsaEncrypted = encryptRSA(rsaData, rsaPublicKey);
        String rsaDecrypted = decryptRSA(rsaEncrypted, rsaPrivateKey);

        System.out.println("\nRSA Encrypted: " + rsaEncrypted);
        System.out.println("RSA Decrypted: " + rsaDecrypted);

        System.out.print("Do you want to export the RSA public key? (yes/no): ");
        if (scanner.nextLine().equalsIgnoreCase("yes")) {
            System.out.print("Enter filename to save the RSA public key: ");
            assert rsaPublicKey != null;
            exportRSAKey(rsaPublicKey, scanner.nextLine());
        }

        System.out.print("Do you want to export the RSA private key? (yes/no): ");
        if (scanner.nextLine().equalsIgnoreCase("yes")) {
            System.out.print("Enter filename to save the RSA private key: ");
            assert rsaPrivateKey != null;
            exportRSAKey(rsaPrivateKey, scanner.nextLine());
        }

        System.out.println("\n### Hybrid Encryption (AES + RSA) ###");
        assert aesKey != null;
        String encryptedAESKey = encryptRSA(Base64.getEncoder().encodeToString(aesKey.getEncoded()), rsaPublicKey);
        System.out.println("AES key encrypted with RSA: " + encryptedAESKey);

        String decryptedAESKey = decryptRSA(encryptedAESKey, rsaPrivateKey);
        SecretKey recoveredAESKey = new SecretKeySpec(Base64.getDecoder().decode(decryptedAESKey), "AES");
        System.out.println("Recovered AES key: " + Base64.getEncoder().encodeToString(recoveredAESKey.getEncoded()));
    }
}
