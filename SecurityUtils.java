import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class SecurityUtils {
    private KeyPair keyPair; // Para kluczy RSA (publiczny i prywatny)
    private PublicKey partnerPublicKey; // Klucz publiczny partnera
    private SecretKey aesKey; // Klucz AES do szyfrowania symetrycznego
    private final SecureRandom secureRandom; // Generator liczb losowych

    public SecurityUtils() throws NoSuchAlgorithmException {
        this.keyPair = generateKeyPair(); // Generowanie pary kluczy RSA
        this.secureRandom = new SecureRandom(); // Inicjalizacja generatora liczb losowych
        this.aesKey = generateAESKey(); // Generowanie klucza AES
    }

    // Generowanie pary kluczy RSA
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Ustawienie długości klucza na 2048 bitów
        return keyPairGenerator.generateKeyPair(); // Generowanie pary kluczy
    }

    // Generowanie klucza AES
    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Ustawienie długości klucza na 256 bitów
        return keyGen.generateKey(); // Generowanie klucza AES
    }

    // Generowanie wyzwania do uwierzytelnienia
    public byte[] generateChallenge() {
        byte[] challenge = new byte[32]; // Tworzenie tablicy bajtów o długości 32
        secureRandom.nextBytes(challenge); // Wypełnianie tablicy losowymi bajtami
        return challenge; // Zwracanie wyzwania
    }

    // Podpisywanie wyzwania
    public byte[] signChallenge(byte[] challenge) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate()); // Inicjalizacja podpisywania kluczem prywatnym
        signature.update(challenge); // Aktualizacja podpisu o dane wyzwania
        return signature.sign(); // Zwracanie podpisanego wyzwania
    }

    // Weryfikacja podpisu wyzwania
    public boolean verifyChallenge(byte[] challenge, byte[] signedChallenge, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey); // Inicjalizacja weryfikacji kluczem publicznym
        signature.update(challenge); // Aktualizacja weryfikacji o dane wyzwania
        return signature.verify(signedChallenge); // Zwracanie wyniku weryfikacji
    }

    // Szyfrowanie danych za pomocą AES
    public byte[] encryptAES(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey); // Inicjalizacja szyfrowania kluczem AES
        return cipher.doFinal(data.getBytes()); // Zwracanie zaszyfrowanych danych
    }

    // Deszyfrowanie danych za pomocą AES
    public String decryptAES(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey); // Inicjalizacja deszyfrowania kluczem AES
        byte[] decryptedBytes = cipher.doFinal(encryptedData); // Deszyfrowanie danych
        return new String(decryptedBytes); // Zwracanie odszyfrowanych danych jako String
    }

    // Szyfrowanie klucza AES za pomocą klucza publicznego RSA
    public byte[] encryptAESKey(PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey); // Inicjalizacja szyfrowania kluczem publicznym RSA
        return cipher.doFinal(aesKey.getEncoded()); // Zwracanie zaszyfrowanego klucza AES
    }

    // Ustawianie klucza AES z zaszyfrowanego klucza
    public void setAESKeyFromEncrypted(byte[] encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate()); // Inicjalizacja deszyfrowania kluczem prywatnym RSA
        byte[] decryptedKey = cipher.doFinal(encryptedKey); // Deszyfrowanie klucza AES
        this.aesKey = new SecretKeySpec(decryptedKey, "AES"); // Ustawianie klucza AES
    }

    // Ustawianie klucza publicznego partnera
    public void setPartnerPublicKey(PublicKey publicKey) {
        this.partnerPublicKey = publicKey;
    }

    // Pobieranie klucza publicznego
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    // Kodowanie wiadomości z podpisem
    public String encodeMessage(String message, byte[] signature) throws Exception {
        byte[] encryptedData = encryptAES(message); // Szyfrowanie wiadomości za pomocą AES
        String encodedData = Base64.getEncoder().encodeToString(encryptedData); // Kodowanie zaszyfrowanych danych do Base64
        String encodedSignature = Base64.getEncoder().encodeToString(signature); // Kodowanie podpisu do Base64
        return encodedData + "#signature:" + encodedSignature; // Zwracanie zakodowanej wiadomości z podpisem
    }

    // Dekodowanie wiadomości z podpisem
    public String[] decodeMessage(String encodedMessage) throws Exception {
        String[] parts = encodedMessage.split("#signature:"); // Rozdzielanie wiadomości i podpisu
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid message format");
        }
        // Deszyfrowanie wiadomości używając AES
        byte[] encryptedData = Base64.getDecoder().decode(parts[0]);
        String decryptedMessage = decryptAES(encryptedData); // Odszyfrowanie wiadomości
        System.out.println("Odszyfrowana wiadomość: " + decryptedMessage);
        return new String[]{decryptedMessage, parts[1]}; // Zwracanie odszyfrowanej wiadomości i podpisu
    }

    // Podpisywanie danych
    public byte[] sign(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedData = digest.digest(data.getBytes(StandardCharsets.UTF_8)); // Haszowanie danych

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate()); // Inicjalizacja podpisywania kluczem prywatnym
        signature.update(hashedData); // Aktualizacja podpisu o dane haszowane
        return signature.sign(); // Zwracanie podpisu
    }

    // Weryfikacja podpisu danych
    public boolean verify(String data, byte[] signedData, PublicKey publicKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedData = digest.digest(data.getBytes(StandardCharsets.UTF_8)); // Haszowanie danych

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey); // Inicjalizacja weryfikacji kluczem publicznym
        signature.update(hashedData); // Aktualizacja weryfikacji o dane haszowane
        return signature.verify(signedData); // Zwracanie wyniku weryfikacji
    }
}