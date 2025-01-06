import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class Client {
    private static SecurityUtils securityUtils; // Narzędzie do operacji kryptograficznych
    private static PublicKey serverPublicKey; // Klucz publiczny serwera

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in); // Scanner do odczytu danych wejściowych od użytkownika
        String line = null; // Zmienna do przechowywania wprowadzonych danych
        boolean czyZalogowany = false; // Flaga określająca, czy użytkownik jest zalogowany
        String loginZalogowanego = null; // Login zalogowanego użytkownika

        System.out.println("Uruchamianie klienta...");

        try {
            // Inicjalizacja narzędzi kryptograficznych
            securityUtils = new SecurityUtils();
            System.out.println("Inicjalizacja zabezpieczeń zakończona");

            // Połączenie z serwerem
            Socket socket = new Socket("localhost", 1410);
            System.out.println("Połączono z serwerem!");

            ObjectOutputStream objOut = new ObjectOutputStream(socket.getOutputStream()); // Strumień wyjściowy do wysyłania obiektów
            ObjectInputStream objIn = new ObjectInputStream(socket.getInputStream()); // Strumień wejściowy do odbierania obiektów

            // Krok 1: Wymiana kluczy publicznych
            objOut.writeObject(securityUtils.getPublicKey()); // Wysyłanie klucza publicznego klienta
            serverPublicKey = (PublicKey) objIn.readObject(); // Odbieranie klucza publicznego serwera
            securityUtils.setPartnerPublicKey(serverPublicKey); // Ustawianie klucza publicznego serwera

            // Krok 2: Uwierzytelnienie serwera
            byte[] serverChallenge = (byte[]) objIn.readObject(); // Odbieranie wyzwania od serwera
            byte[] serverResponse = securityUtils.signChallenge(serverChallenge); // Podpisywanie wyzwania
            objOut.writeObject(serverResponse); // Wysyłanie podpisanego wyzwania

            // Krok 3: Uwierzytelnienie klienta
            byte[] clientChallenge = securityUtils.generateChallenge(); // Generowanie wyzwania dla serwera
            objOut.writeObject(clientChallenge); // Wysyłanie wyzwania do serwera
            byte[] signedServerChallenge = (byte[]) objIn.readObject(); // Odbieranie podpisanego wyzwania od serwera
            boolean serverVerified = securityUtils.verifyChallenge(clientChallenge, signedServerChallenge, serverPublicKey); // Weryfikacja podpisu

            if (!serverVerified) {
                throw new SecurityException("Nie udało się zweryfikować tożsamości serwera!");
            }
            System.out.println("Zweryfikowano tożsamość serwera");

            // Krok 4: Wymiana klucza AES
            byte[] encryptedAESKey = (byte[]) objIn.readObject(); // Odbieranie zaszyfrowanego klucza AES
            securityUtils.setAESKeyFromEncrypted(encryptedAESKey); // Ustawianie klucza AES

            PrintWriter out = new PrintWriter(socket.getOutputStream(), true); // Strumień wyjściowy do wysyłania danych
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream())); // Strumień wejściowy do odbierania danych

            // Główna pętla obsługująca interakcje użytkownika
            while (!"exit".equalsIgnoreCase(line)) {
                menu(czyZalogowany); // Wyświetlanie menu
                line = sc.nextLine(); // Odczytanie wyboru użytkownika

                switch (line) {
                    case "1": {
                        // Logowanie użytkownika
                        System.out.print("Wpisz nazwę użytkownika: ");
                        String login = sc.nextLine();
                        System.out.print("Wpisz hasło: ");
                        String haslo = sc.nextLine();
                        StringJoiner loginPacket = new StringJoiner("#");
                        loginPacket.add("type:login");
                        loginPacket.add("login:" + login);
                        loginPacket.add("haslo:" + haslo);

                        String packet = loginPacket.toString();
                        byte[] signature = securityUtils.sign(packet); // Podpisywanie pakietu
                        String encodedMessage = securityUtils.encodeMessage(packet, signature); // Kodowanie wiadomości
                        out.println(encodedMessage); // Wysyłanie wiadomości

                        String encodedResponse = in.readLine(); // Odbieranie odpowiedzi
                        String[] parts = securityUtils.decodeMessage(encodedResponse); // Dekodowanie odpowiedzi
                        String response = parts[0];
                        byte[] responseSignature = Base64.getDecoder().decode(parts[1]);

                        if (securityUtils.verify(response, responseSignature, serverPublicKey)) { // Weryfikacja podpisu
                            String[] splittedResponse = response.split(":");
                            if (splittedResponse[1].equals("OK")) {
                                czyZalogowany = true;
                                loginZalogowanego = login;
                                System.out.println("Zalogowano pomyślnie");
                            } else {
                                System.out.println("Błąd logowania - nieprawidłowe dane");
                            }
                        } else {
                            System.out.println("Ostrzeżenie: Otrzymano nieprawidłowo podpisaną odpowiedź!");
                        }
                        break;
                    }
                    case "2": {
                        // Rejestracja nowego użytkownika
                        System.out.print("Podaj login: ");
                        String nowyLogin = sc.nextLine();
                        System.out.print("Podaj haslo: ");
                        String nowyHaslo = sc.nextLine();
                        StringJoiner registerPacket = new StringJoiner("#");
                        registerPacket.add("type:register");
                        registerPacket.add("login:" + nowyLogin);
                        registerPacket.add("haslo:" + nowyHaslo);

                        String packet = registerPacket.toString();
                        byte[] signature = securityUtils.sign(packet); // Podpisywanie pakietu
                        out.println(securityUtils.encodeMessage(packet, signature)); // Kodowanie i wysyłanie wiadomości

                        String encodedResponse = in.readLine(); // Odbieranie odpowiedzi
                        String[] parts = securityUtils.decodeMessage(encodedResponse); // Dekodowanie odpowiedzi
                        String response = parts[0];
                        byte[] responseSignature = Base64.getDecoder().decode(parts[1]);

                        if (securityUtils.verify(response, responseSignature, serverPublicKey)) { // Weryfikacja podpisu
                            String[] splittedResponse = response.split(":");
                            if (splittedResponse[1].equals("OK")) {
                                System.out.println("Zarejestrowano pomyślnie");
                            } else {
                                System.out.println("Błąd rejestracji - login już istnieje");
                            }
                        }
                        break;
                    }
                    case "3": {
                        // Pobieranie tablicy wiadomości
                        String tablicaPacket = "type:tablica";
                        byte[] signature = securityUtils.sign(tablicaPacket); // Podpisywanie pakietu
                        out.println(securityUtils.encodeMessage(tablicaPacket, signature)); // Kodowanie i wysyłanie wiadomości

                        String encodedResponse = in.readLine(); // Odbieranie odpowiedzi
                        String[] parts = securityUtils.decodeMessage(encodedResponse); // Dekodowanie odpowiedzi
                        String response = parts[0];
                        byte[] responseSignature = Base64.getDecoder().decode(parts[1]);

                        if (securityUtils.verify(response, responseSignature, serverPublicKey)) { // Weryfikacja podpisu
                            String[] splittedResponse = response.split("#|:");
                            if (splittedResponse[1].equals("OK")) {
                                odczytajTablice(response); // Odczytanie i wyświetlenie tablicy
                            } else {
                                System.out.println("Nie udało pobrać się danych z tablicy");
                            }
                        }
                        break;
                    }
                    case "4": {
                        // Dodawanie nowej wiadomości na tablicy
                        if (!czyZalogowany) {
                            System.out.println("Musisz być zalogowany aby dodać wpis");
                            break;
                        }
                        System.out.println("Wpisz treść swojego wpisu: ");
                        String tresc = sc.nextLine();
                        StringJoiner chatPacket = new StringJoiner("#");
                        chatPacket.add("type:chat");
                        chatPacket.add("login:" + loginZalogowanego);
                        chatPacket.add("tresc:" + tresc);

                        String packet = chatPacket.toString();
                        byte[] signature = securityUtils.sign(packet); // Podpisywanie pakietu
                        out.println(securityUtils.encodeMessage(packet, signature)); // Kodowanie i wysyłanie wiadomości

                        String encodedResponse = in.readLine(); // Odbieranie odpowiedzi
                        String[] parts = securityUtils.decodeMessage(encodedResponse); // Dekodowanie odpowiedzi
                        String response = parts[0];
                        byte[] responseSignature = Base64.getDecoder().decode(parts[1]);

                        if (securityUtils.verify(response, responseSignature, serverPublicKey)) { // Weryfikacja podpisu
                            String[] splittedResponse = response.split(":");
                            if (splittedResponse[1].equals("OK")) {
                                System.out.println("Dodano wpis pomyślnie");
                            } else {
                                System.out.println("Błąd podczas dodawania wpisu");
                            }
                        }
                        break;
                    }
                    case "5": {
                        // Pobieranie pliku z serwera
                        if (!czyZalogowany) {
                            System.out.println("Musisz być zalogowany aby pobrać plik");
                            break;
                        }
                        System.out.println("Podaj nazwę pliku:");
                        String nazwaPliku = sc.nextLine();
                        StringJoiner newFTIpacket = new StringJoiner("#");
                        newFTIpacket.add("type:FTI");
                        newFTIpacket.add("login:" + loginZalogowanego);
                        newFTIpacket.add("filename:" + nazwaPliku);

                        String packet = newFTIpacket.toString();
                        byte[] signature = securityUtils.sign(packet); // Podpisywanie pakietu
                        out.println(securityUtils.encodeMessage(packet, signature)); // Kodowanie i wysyłanie wiadomości

                        ArrayList<String> packetsRecivedList = new ArrayList<String>();
                        String encodedResponse = in.readLine(); // Odbieranie odpowiedzi
                        String[] parts = securityUtils.decodeMessage(encodedResponse); // Dekodowanie odpowiedzi
                        String response = parts[0];
                        byte[] responseSignature = Base64.getDecoder().decode(parts[1]);

                        if (securityUtils.verify(response, responseSignature, serverPublicKey)) { // Weryfikacja podpisu
                            String[] recivedPacket = response.split("#|:");
                            if (recivedPacket[1].equals("OK")) {
                                int packetNo = Integer.parseInt(recivedPacket[5]);
                                int packetsRecived = 1;
                                while (packetsRecived < packetNo) {
                                    packetsRecivedList.add(response);
                                    encodedResponse = in.readLine(); // Odbieranie kolejnych pakietów
                                    parts = securityUtils.decodeMessage(encodedResponse); // Dekodowanie pakietów
                                    response = parts[0];
                                    packetsRecived++;
                                }
                                if (packetNo == 1) {
                                    packetsRecivedList.add(response);
                                }
                                System.out.println("Odebrano wszystkie paczki");

                                String[] splittedPacket;
                                String newFileName = "";
                                ArrayList<byte[]> newFileContentList = new ArrayList<>();
                                for (int i = 0; i < packetsRecivedList.size(); i++) {
                                    splittedPacket = packetsRecivedList.get(i).split("#|:");
                                    byte[] recivedContent = Base64.getDecoder().decode(splittedPacket[7]);
                                    newFileContentList.add(recivedContent);
                                    if (i == 0) {
                                        newFileName = splittedPacket[3];
                                    }
                                }
                                String newPath = "C:\\Moje_pliki\\" + newFileName;
                                File file = new File(newPath);
                                boolean isExsisting = file.exists();
                                if (isExsisting) {
                                    System.out.println("Istnieje plik o tej samej nazwie");
                                    break;
                                }
                                try (OutputStream outputStream = new FileOutputStream(file)) {
                                    for (byte[] content : newFileContentList) {
                                        outputStream.write(content);
                                    }
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }
                                System.out.println("Poprawnie pobrano plik.");
                            } else {
                                System.out.println("Nie udało się pobrać pliku sprawdź logi w FileTransferIn");
                            }
                        }
                        break;
                    }
                    case "6": {
                        // Wysyłanie pliku na serwer
                        if (!czyZalogowany) {
                            System.out.println("Musisz być zalogowany aby wysłać plik");
                            break;
                        }
                        String[] pathnames;
                        String path = "C:\\Moje_pliki\\";
                        File file = new File(path);
                        pathnames = file.list();
                        int fileNo = 1;
                        if (pathnames == null) {
                            System.out.println("w tym folderze nie ma plików");
                            break;
                        } else {
                            for (String pathname : pathnames) {
                                System.out.println(fileNo + ". " + pathname);
                                fileNo++;
                            }
                        }
                        System.out.println("Wybierz plik który chcesz wysłać:");
                        int wybor = sc.nextInt() - 1;
                        File fileToSend = new File("C:\\Moje_pliki\\" + pathnames[wybor]);
                        long fileSize = fileToSend.length();
                        int packetCount = (int) Math.ceil((double) fileSize / 1024);
                        InputStream fileInputStream = new FileInputStream(fileToSend);
                        byte[] buffer = new byte[1024];
                        StringJoiner newFTOpacket = new StringJoiner("#");
                        int bytesRead;
                        for (int i = 0; i < packetCount; i++) {
                            bytesRead = fileInputStream.read(buffer);
                            byte[] packetToAdd = new byte[bytesRead];
                            System.arraycopy(buffer, 0, packetToAdd, 0, bytesRead);
                            newFTOpacket.add("type:FTO");
                            newFTOpacket.add("login:" + loginZalogowanego);
                            newFTOpacket.add("filename:" + fileToSend.getName());
                            newFTOpacket.add("packetsNo:" + packetCount);
                            newFTOpacket.add("content:" + Base64.getEncoder().encodeToString(packetToAdd));

                            String packet = newFTOpacket.toString();
                            byte[] signature = securityUtils.sign(packet); // Podpisywanie pakietu
                            out.println(securityUtils.encodeMessage(packet, signature)); // Kodowanie i wysyłanie wiadomości
                            newFTOpacket = new StringJoiner("#");
                        }

                        String encodedResponse = in.readLine(); // Odbieranie odpowiedzi
                        String[] parts = securityUtils.decodeMessage(encodedResponse); // Dekodowanie odpowiedzi
                        String response = parts[0];
                        byte[] responseSignature = Base64.getDecoder().decode(parts[1]);

                        if (securityUtils.verify(response, responseSignature, serverPublicKey)) { // Weryfikacja podpisu
                            String[] splittedResponse = response.split(":");
                            if (splittedResponse[1].equals("OK")) {
                                System.out.println("Plik wysłano pomyślnie");
                            } else {
                                System.out.println("Wystąpił problem z przesyłaniem pliku sprawdź logi w klasie FileTransferOut");
                            }
                        }
                        break;
                    }
                    case "7":
                        // Wylogowanie użytkownika
                        if (czyZalogowany) {
                            czyZalogowany = false;
                            loginZalogowanego = null;
                            System.out.println("Wylogowano pomyślnie");
                        } else {
                            System.out.println("Nie jesteś zalogowany");
                        }
                        break;
                    case "man":
                        // Wyświetlenie systemu pomocy
                        wyswietlPomoc();
                        break;
                    case "exit":
                        // Zamykanie aplikacji
                        System.out.println("Zamykanie aplikacji...");
                        socket.close();
                        break;
                    default:
                        System.out.println("Nieprawidłowa opcja. Wybierz ponownie.");
                }
            }
            sc.close();
        } catch (Exception e) {
            System.out.println("Błąd połączenia z serwerem: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Wyświetlenie menu w zależności od statusu logowania
    public static void menu(boolean czyZalogowany) {
        if (czyZalogowany) {
            System.out.println("\nWpisz numer funkcji:");
            System.out.println("3. Tablica");
            System.out.println("4. Chat");
            System.out.println("5. Transferin");
            System.out.println("6. TransferOut");
            System.out.println("7. Logout");
            System.out.print("Wybór: ");
        } else {
            System.out.println("\nWpisz numer funkcji:");
            System.out.println("1. Login");
            System.out.println("2. Register");
            System.out.println("3. Tablica");
            System.out.println("man. Jeżeli chcesz uzyskać pomoc wpisz 'man'");
            System.out.print("Wybór: ");
        }
    }

    // Wyświetlenie systemu pomocy
    private static void wyswietlPomoc() {
        System.out.println("\nSystem pomocy:");
        System.out.println("1. Logowanie - służy do logowania użytkownika");
        System.out.println("2. Rejestracja - służy do rejestracji nowego użytkownika");
        System.out.println("3. Pobierz tablicę - pobiera listę wpisów z tablicy");
        System.out.println("4. Dodaj wpis - dodaje nowy wpis na tablicy");
        System.out.println("5. Pobierz plik - pobiera plik z serwera");
        System.out.println("6. Wyślij plik - wysyła plik na serwer");
        System.out.println("man - wyświetla system pomocy");
        System.out.println("exit - wyjście z programu");
    }

    // Odczytanie i wyświetlenie tablicy wiadomości
    public static void odczytajTablice(String odpowiedz) {
        String[] entries = odpowiedz.split("#");
        for (int i = 1; i < entries.length; i++) {
            String[] entryDetails = entries[i].split(":");
            if (entryDetails.length == 2) {
                System.out.println(entryDetails[0] + " napisał: " + entryDetails[1]);
            }
        }
    }
}