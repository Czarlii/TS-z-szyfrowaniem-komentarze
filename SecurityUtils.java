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

//     Wyjaśnienie:
// Deklaracja klasy SecurityUtils:  
// public class SecurityUtils {
// Definiuje publiczną klasę SecurityUtils, która będzie zawierać metody i zmienne związane z operacjami kryptograficznymi.
// Deklaracja zmiennych:  
// private KeyPair keyPair; // Para kluczy RSA (publiczny i prywatny)
// private PublicKey partnerPublicKey; // Klucz publiczny partnera
// private SecretKey aesKey; // Klucz AES do szyfrowania symetrycznego
// private final SecureRandom secureRandom; // Generator liczb losowych
// keyPair: Przechowuje parę kluczy RSA (klucz publiczny i prywatny).
// partnerPublicKey: Przechowuje klucz publiczny partnera, który może być używany do szyfrowania lub weryfikacji podpisów.
// aesKey: Przechowuje klucz AES używany do szyfrowania symetrycznego.
// secureRandom: Generator liczb losowych używany do generowania wyzwań i innych operacji kryptograficznych. Jest oznaczony jako final, co oznacza, że jego wartość nie może być zmieniona po inicjalizacji.
// Konstruktor klasy SecurityUtils:  
// public SecurityUtils() throws NoSuchAlgorithmException {
//     this.keyPair = generateKeyPair(); // Generowanie pary kluczy RSA
//     this.secureRandom = new SecureRandom(); // Inicjalizacja generatora liczb losowych
//     this.aesKey = generateAESKey(); // Generowanie klucza AES
// }
// Konstruktor jest wywoływany podczas tworzenia nowego obiektu SecurityUtils.
// this.keyPair = generateKeyPair();: Wywołuje metodę generateKeyPair(), która generuje parę kluczy RSA i przypisuje ją do zmiennej keyPair.
// this.secureRandom = new SecureRandom();: Inicjalizuje generator liczb losowych secureRandom.
// this.aesKey = generateAESKey();: Wywołuje metodę generateAESKey(), która generuje klucz AES i przypisuje go do zmiennej aesKey.
// Podsumowanie:
// Ten fragment kodu definiuje klasę SecurityUtils, która zarządza operacjami kryptograficznymi, takimi jak generowanie kluczy RSA i AES oraz inicjalizacja generatora liczb losowych. Konstruktor klasy inicjalizuje te zmienne, aby były gotowe do użycia w innych metodach klasy.

    // Generowanie pary kluczy RSA
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Ustawienie długości klucza na 2048 bitów
        return keyPairGenerator.generateKeyPair(); // Generowanie pary kluczy
    }

//     Deklaracja metody: private KeyPair generateKeyPair() throws NoSuchAlgorithmException - Metoda jest prywatna, co oznacza, że jest dostępna tylko w obrębie klasy SecurityUtils. Zwraca obiekt typu KeyPair i może rzucić wyjątek NoSuchAlgorithmException, jeśli algorytm RSA nie jest dostępny w środowisku wykonawczym.  
// Inicjalizacja generatora pary kluczy: KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); - Tworzy instancję KeyPairGenerator dla algorytmu RSA. KeyPairGenerator jest klasą dostarczającą funkcjonalność do generowania par kluczy publicznych i prywatnych.  
// Ustawienie długości klucza: keyPairGenerator.initialize(2048); - Ustawia długość klucza na 2048 bitów. Długość klucza jest ważnym parametrem, który wpływa na bezpieczeństwo kryptograficzne; 2048 bitów jest obecnie uważane za bezpieczną długość klucza dla większości zastosowań.  
// Generowanie pary kluczy: return keyPairGenerator.generateKeyPair(); - Generuje parę kluczy (publiczny i prywatny) i zwraca ją jako obiekt KeyPair.

    // Generowanie klucza AES
    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Ustawienie długości klucza na 256 bitów
        return keyGen.generateKey(); // Generowanie klucza AES
    }

//     Deklaracja metody: private SecretKey generateAESKey() throws NoSuchAlgorithmException - Metoda jest prywatna, co oznacza, że jest dostępna tylko w obrębie klasy SecurityUtils. Zwraca obiekt typu SecretKey i może rzucić wyjątek NoSuchAlgorithmException.  
// Inicjalizacja generatora kluczy: KeyGenerator keyGen = KeyGenerator.getInstance("AES"); - Tworzy instancję KeyGenerator dla algorytmu AES (Advanced Encryption Standard).  
// Ustawienie długości klucza: keyGen.init(256); - Ustawia długość klucza na 256 bitów, co jest standardem dla silnego szyfrowania AES.  
// Generowanie klucza: return keyGen.generateKey(); - Generuje i zwraca nowy klucz AES.

    // Generowanie wyzwania do uwierzytelnienia
    public byte[] generateChallenge() {
        byte[] challenge = new byte[32]; // Tworzenie tablicy bajtów o długości 32
        secureRandom.nextBytes(challenge); // Wypełnianie tablicy losowymi bajtami
        return challenge; // Zwracanie wyzwania
    }

//     Deklaracja metody: Metoda generateChallenge jest zadeklarowana, aby zwracać tablicę bajtów (byte[]).
// Inicjalizacja tablicy bajtów: Tworzona jest tablica bajtów o nazwie challenge o długości 32. Ta tablica będzie przechowywać losowe bajty.
// Generowanie losowych bajtów: Obiekt secureRandom, który jest instancją klasy SecureRandom, wypełnia tablicę challenge losowymi bajtami.
// Instrukcja zwracająca: Metoda zwraca tablicę challenge zawierającą losowe bajty.
// Metoda ta jest zazwyczaj używana w protokołach bezpieczeństwa do generowania losowego wyzwania, które może być podpisane lub zaszyfrowane do celów uwierzytelnienia.

    // Podpisywanie wyzwania
    public byte[] signChallenge(byte[] challenge) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate()); // Inicjalizacja podpisywania kluczem prywatnym
        signature.update(challenge); // Aktualizacja podpisu o dane wyzwania
        return signature.sign(); // Zwracanie podpisanego wyzwania
    }

//     Inicjalizacja obiektu Signature:  
// Signature signature = Signature.getInstance("SHA256withRSA");
// Tworzy obiekt Signature używający algorytmu SHA-256 z RSA.  
// Inicjalizacja podpisywania kluczem prywatnym:  
// signature.initSign(keyPair.getPrivate());
// Inicjalizuje obiekt Signature do podpisywania, używając prywatnego klucza z pary kluczy RSA.  
// Aktualizacja podpisu o dane wyzwania:  
// signature.update(challenge);
// Dodaje dane wyzwania do obiektu Signature, które będą podpisane.  
// Podpisywanie danych:  
// return signature.sign();
// Generuje i zwraca podpisane dane wyzwania.
    
    // Weryfikacja podpisu wyzwania
    public boolean verifyChallenge(byte[] challenge, byte[] signedChallenge, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey); // Inicjalizacja weryfikacji kluczem publicznym
        signature.update(challenge); // Aktualizacja weryfikacji o dane wyzwania
        return signature.verify(signedChallenge); // Zwracanie wyniku weryfikacji
    }

// Tworzenie obiektu Signature:  
// Signature signature = Signature.getInstance("SHA256withRSA");
// To jakbyśmy przygotowywali narzędzie do sprawdzania podpisów.
// Inicjalizacja weryfikacji:  
// signature.initVerify(publicKey);
// Mówimy naszemu narzędziu, że będziemy używać klucza publicznego do sprawdzania podpisu.
// Aktualizacja narzędzia o dane wyzwania:  
// signature.update(challenge);
// Dajemy naszemu narzędziu dane, które mają być sprawdzone.
// Sprawdzanie podpisu:  
// return signature.verify(signedChallenge);
// Narzędzie sprawdza, czy podpis jest prawidłowy i zwraca wynik (prawda/fałsz).

    // Szyfrowanie danych za pomocą AES
    public byte[] encryptAES(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey); // Inicjalizacja szyfrowania kluczem AES
        return cipher.doFinal(data.getBytes()); // Zwracanie zaszyfrowanych danych
    }

//     Tworzenie obiektu Cipher: Cipher cipher = Cipher.getInstance("AES");  
// To jakbyś brał specjalne narzędzie do szyfrowania danych.
// Inicjalizacja szyfrowania: cipher.init(Cipher.ENCRYPT_MODE, aesKey);  
// Mówisz narzędziu, że chcesz szyfrować dane i podajesz mu klucz AES, który jest jak tajny kod.
// Szyfrowanie danych: return cipher.doFinal(data.getBytes());  
// Narzędzie bierze twoje dane (zamienia je na bajty) i szyfruje je, zwracając zaszyfrowane dane.
// Cały ten proces sprawia, że twoje dane są bezpieczne i nikt nie może ich odczytać bez odpowiedniego klucza AES

    // Deszyfrowanie danych za pomocą AES
    public String decryptAES(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey); // Inicjalizacja deszyfrowania kluczem AES
        byte[] decryptedBytes = cipher.doFinal(encryptedData); // Deszyfrowanie danych
        return new String(decryptedBytes); // Zwracanie odszyfrowanych danych jako String
    }
// Cipher: To taki magiczny klucz, który zamienia wiadomości w tajemnicze kody, żeby nikt inny nie mógł ich przeczytać.
// SecretKey: To specjalny klucz, który pomaga w zamienianiu wiadomości w tajemnicze kody i z powrotem w normalne wiadomości.
// aesKey: To nasz specjalny klucz, który używamy do zamieniania wiadomości w tajemnicze kody i z powrotem w normalne wiadomości.
// encryptedData: To wiadomość, która została zamieniona w tajemniczy kod.
// decryptedBytes: To wiadomość, która została zamieniona z powrotem z tajemniczego kodu w normalną wiadomość.

    
    
    
    // Szyfrowanie klucza AES za pomocą klucza publicznego RSA
    public byte[] encryptAESKey(PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey); // Inicjalizacja szyfrowania kluczem publicznym RSA
        return cipher.doFinal(aesKey.getEncoded()); // Zwracanie zaszyfrowanego klucza AES
    }
//     Metoda encryptAESKey: Ta metoda przyjmuje klucz publiczny jako argument.
// Tworzenie obiektu Cipher: Używasz klasy Cipher do szyfrowania danych. W tym przypadku używasz algorytmu RSA.
// Inicjalizacja szyfrowania: Inicjalizujesz obiekt Cipher w trybie szyfrowania (ENCRYPT_MODE) z użyciem klucza publicznego.
// Szyfrowanie klucza AES: Szyfrujesz klucz AES (który jest zakodowany jako tablica bajtów) za pomocą metody doFinal.
// Zwracanie zaszyfrowanego klucza: Metoda zwraca zaszyfrowany klucz AES jako tablicę bajtów.

    // Ustawianie klucza AES z zaszyfrowanego klucza
    public void setAESKeyFromEncrypted(byte[] encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate()); // Inicjalizacja deszyfrowania kluczem prywatnym RSA
        byte[] decryptedKey = cipher.doFinal(encryptedKey); // Deszyfrowanie klucza AES
        this.aesKey = new SecretKeySpec(decryptedKey, "AES"); // Ustawianie klucza AES
    }
//     W tym kodzie masz funkcję, która bierze zaszyfrowany klucz AES i zamienia go z powrotem na zwykły klucz AES, który można użyć do szyfrowania i deszyfrowania danych. Oto jak to działa krok po kroku:  
// Zaszyfrowany klucz AES: Na początku masz zaszyfrowany klucz AES, który jest w postaci bajtów (byte[]).  
// Tworzenie obiektu Cipher: Tworzysz obiekt Cipher, który jest narzędziem do szyfrowania i deszyfrowania danych. Używasz algorytmu RSA do deszyfrowania.  
// Inicjalizacja deszyfrowania: Inicjalizujesz obiekt Cipher do trybu deszyfrowania (DECRYPT_MODE) i używasz swojego prywatnego klucza RSA (keyPair.getPrivate()).  
// Deszyfrowanie klucza AES: Używasz obiektu Cipher do deszyfrowania zaszyfrowanego klucza AES. Wynik to zwykły klucz AES w postaci bajtów.  
// Tworzenie klucza AES: Tworzysz nowy klucz AES (SecretKeySpec) z odszyfrowanych bajtów i zapisujesz go w zmiennej aesKey.

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
//         Ustawianie klucza publicznego partnera:  
// public void setPartnerPublicKey(PublicKey publicKey) {
//     this.partnerPublicKey = publicKey;
// }
// Ta metoda pozwala ustawić klucz publiczny partnera. Klucz publiczny jest używany do szyfrowania danych, które partner może odszyfrować swoim kluczem prywatnym.
// Pobieranie klucza publicznego:  
// public PublicKey getPublicKey() {
//     return keyPair.getPublic();
// }
// Ta metoda zwraca klucz publiczny z pary kluczy (publiczny i prywatny), które zostały wygenerowane. Klucz publiczny może być udostępniony innym, aby mogli szyfrować dane dla nas.
// Kodowanie wiadomości z podpisem:
// public String encodeMessage(String message, byte[] signature) throws Exception {
//     byte[] encryptedData = encryptAES(message); // Szyfrowanie wiadomości za pomocą AES
//     String encodedData = Base64.getEncoder().encodeToString(encryptedData); // Kodowanie zaszyfrowanych danych do Base64
//     String encodedSignature = Base64.getEncoder().encodeToString(signature); // Kodowanie podpisu do Base64
//     return encodedData + "#signature:" + encodedSignature; // Zwracanie zakodowanej wiadomości z podpisem
// }
// Ta metoda koduje wiadomość i jej podpis.
// Najpierw szyfruje wiadomość za pomocą AES (szyfrowanie symetryczne).
// Następnie koduje zaszyfrowane dane i podpis do formatu Base64 (czyli zamienia je na ciąg znaków, który można łatwo przesyłać).
// Na końcu łączy zakodowane dane i podpis w jeden ciąg znaków, który można przesłać.

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
//     Rozdziela wiadomość i podpis:  
// Wiadomość jest podzielona na dwie części: zaszyfrowaną wiadomość i podpis.
// Używa do tego split("#signature:").
// Sprawdza, czy format wiadomości jest poprawny:  
// Jeśli wiadomość nie ma dwóch części, rzuca wyjątek IllegalArgumentException.
// Deszyfruje wiadomość:  
// Zaszyfrowana wiadomość jest dekodowana z formatu Base64.
// Następnie jest deszyfrowana za pomocą metody decryptAES.
// Zwraca odszyfrowaną wiadomość i podpis:  
// Odszyfrowana wiadomość jest drukowana na konsolę.
// Metoda zwraca tablicę z odszyfrowaną wiadomością i podpisem

    // Podpisywanie danych
    public byte[] sign(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedData = digest.digest(data.getBytes(StandardCharsets.UTF_8)); // Haszowanie danych

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate()); // Inicjalizacja podpisywania kluczem prywatnym
        signature.update(hashedData); // Aktualizacja podpisu o dane haszowane
        return signature.sign(); // Zwracanie podpisu
    }
//     Kod, który wybrałeś, służy do podpisywania danych. Podpisywanie danych to proces, który pozwala upewnić się, że dane pochodzą od właściwej osoby i nie zostały zmienione. Oto jak to działa krok po kroku:  
// Haszowanie danych: Najpierw dane są przekształcane w unikalny skrót (hash) za pomocą algorytmu SHA-256. To jak odcisk palca dla danych - każda zmiana w danych zmienia ich skrót.  
// Podpisywanie skrótu: Następnie ten skrót jest podpisywany za pomocą klucza prywatnego (RSA). Podpisanie oznacza, że skrót jest szyfrowany kluczem prywatnym, co tworzy podpis cyfrowy.  
// Zwracanie podpisu: Na końcu funkcja zwraca ten podpis cyfrowy.  
// Podpis cyfrowy można później zweryfikować za pomocą klucza publicznego, aby upewnić się, że dane nie zostały zmienione i pochodzą od właściwej osoby.

    // Weryfikacja podpisu danych
    public boolean verify(String data, byte[] signedData, PublicKey publicKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedData = digest.digest(data.getBytes(StandardCharsets.UTF_8)); // Haszowanie danych

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey); // Inicjalizacja weryfikacji kluczem publicznym
        signature.update(hashedData); // Aktualizacja weryfikacji o dane haszowane
        return signature.verify(signedData); // Zwracanie wyniku weryfikacji
    }

//     Haszowanie danych:  
// Najpierw dane są haszowane za pomocą algorytmu SHA-256. Haszowanie to proces przekształcania danych w unikalny ciąg bajtów o stałej długości.
// Inicjalizacja weryfikacji:  
// Następnie tworzony jest obiekt Signature z algorytmem SHA256withRSA.
// Obiekt Signature jest inicjalizowany do trybu weryfikacji przy użyciu klucza publicznego.
// Aktualizacja weryfikacji:  
// Obiekt Signature jest aktualizowany o haszowane dane.
// Weryfikacja podpisu:  
// Na końcu obiekt Signature weryfikuje podpisane dane. Jeśli podpis jest prawidłowy, zwraca true, w przeciwnym razie false.
}

// Importy: Klasa importuje różne biblioteki potrzebne do szyfrowania, generowania kluczy, podpisywania danych i kodowania Base64.  
// Deklaracje zmiennych:  
// keyPair: Para kluczy RSA (publiczny i prywatny).
// partnerPublicKey: Klucz publiczny partnera.
// aesKey: Klucz AES do szyfrowania symetrycznego.
// secureRandom: Generator liczb losowych.
// Konstruktor:  
// Inicjalizuje parę kluczy RSA, generator liczb losowych oraz klucz AES.
// Generowanie pary kluczy RSA:  
// Metoda generateKeyPair tworzy generator kluczy RSA, ustawia długość klucza na 2048 bitów i generuje parę kluczy.
// Generowanie klucza AES:  
// Metoda generateAESKey tworzy generator kluczy AES, ustawia długość klucza na 256 bitów i generuje klucz AES.
// Generowanie wyzwania:  
// Metoda generateChallenge tworzy tablicę bajtów o długości 32 i wypełnia ją losowymi bajtami.
// Podpisywanie wyzwania:  
// Metoda signChallenge używa klucza prywatnego do podpisania wyzwania za pomocą algorytmu SHA256 z RSA.
// Weryfikacja podpisu wyzwania:  
// Metoda verifyChallenge używa klucza publicznego do weryfikacji podpisu wyzwania.
// Szyfrowanie danych za pomocą AES:  
// Metoda encryptAES szyfruje dane za pomocą klucza AES.
// Deszyfrowanie danych za pomocą AES:  
// Metoda decryptAES deszyfruje dane za pomocą klucza AES.
// Szyfrowanie klucza AES za pomocą klucza publicznego RSA:  
// Metoda encryptAESKey szyfruje klucz AES za pomocą klucza publicznego RSA.
// Ustawianie klucza AES z zaszyfrowanego klucza:  
// Metoda setAESKeyFromEncrypted deszyfruje zaszyfrowany klucz AES za pomocą klucza prywatnego RSA i ustawia go jako klucz AES.
// Ustawianie klucza publicznego partnera:  
// Metoda setPartnerPublicKey ustawia klucz publiczny partnera.
// Pobieranie klucza publicznego:  
// Metoda getPublicKey zwraca klucz publiczny.
// Kodowanie wiadomości z podpisem:  
// Metoda encodeMessage szyfruje wiadomość za pomoc�� AES, koduje zaszyfrowane dane i podpis do Base64, a następnie zwraca zakodowaną wiadomość z podpisem.
// Dekodowanie wiadomości z podpisem:  
// Metoda decodeMessage rozdziela wiadomość i podpis, deszyfruje wiadomość za pomocą AES i zwraca odszyfrowaną wiadomość oraz podpis.
// Podpisywanie danych:  
// Metoda sign haszuje dane za pomocą SHA-256, a następnie podpisuje je kluczem prywatnym RSA.
// Weryfikacja podpisu danych:
// Metoda verify haszuje dane za pomocą SHA-256, a następnie weryfikuje podpis kluczem publicznym RSA

