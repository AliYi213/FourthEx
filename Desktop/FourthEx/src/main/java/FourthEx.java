import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class FourthEx {
    private static final String ALGORITHM = "RSA";

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Choose an option:");
        System.out.println("1. Encrypt and save to file with digital signature");
        System.out.println("2. Verify digital signature from file");
        int choice = scanner.nextInt();
        scanner.nextLine();

        switch (choice) {
            case 1:
                encryptAndSign(scanner);
                break;
            case 2:
                verifySignature();
                break;
            default:
                System.out.println("Invalid choice");
                break;
        }

        scanner.close();
    }

    private static void encryptAndSign(Scanner scanner) throws Exception {
        System.out.println("Enter plaintext:");
        String plaintext = scanner.nextLine();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(encryptedBytes);
        byte[] digitalSignature = signature.sign();
        String signatureText = Base64.getEncoder().encodeToString(digitalSignature);

        System.out.println("Encrypted Text: " + encryptedText);
        System.out.println("Digital Signature: " + signatureText);

        saveToFile(encryptedText, "cipher.txt");
        saveToFile(Base64.getEncoder().encodeToString(publicKey.getEncoded()), "publickey.txt");
        saveToFile(signatureText, "signature.txt");
    }

    private static void saveToFile(String data, String filename) {
        try (PrintWriter writer = new PrintWriter(filename)) {
            writer.println(data);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    private static String readFromFile(String filename) {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return sb.toString();
    }

    private static void verifySignature() throws Exception {
        String publicKeyString = readFromFile("publickey.txt");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        String encryptedText = readFromFile("cipher.txt");
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        String signatureText = readFromFile("signature.txt");
        byte[] signatureBytes = Base64.getDecoder().decode(signatureText);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(encryptedBytes);

        boolean verified = signature.verify(signatureBytes);
        if (verified) {
            System.out.println("Signature verified.");
        } else {
            System.out.println("Signature verification failed.");
        }
    }
}
