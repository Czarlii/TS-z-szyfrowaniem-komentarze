import java.io.*; // Importowanie klas do obsługi wejścia/wyjścia
import java.net.*; // Importowanie klas do obsługi sieci
import java.security.*; // Importowanie klas do obsługi kryptografii
import java.util.Base64; // Importowanie klasy do kodowania Base64

public class Server {
    public static void main(String[] args) {
        ServerSocket server = null; // Deklaracja zmiennej ServerSocket
        try {
            // Tworzenie serwera nasłuchującego na porcie 1410
            server = new ServerSocket(1410);
            server.setReuseAddress(true); // Ustawienie opcji ponownego użycia adresu
            System.out.println("Serwer uruchomiony i oczekuje na połączenia...");

            while (true) {
                // Akceptowanie połączenia od klienta
                Socket client = server.accept();
                System.out.println("Nowy klient połączony: " + client.getInetAddress().getHostAddress());
                ClientHandler clientSock = new ClientHandler(client); // Tworzenie nowego wątku do obsługi klienta
                new Thread(clientSock).start(); // Uruchomienie wątku
            }
        } catch (IOException e) {
            e.printStackTrace(); // Obsługa błędów wejścia/wyjścia
        } finally {
            if (server != null) {
                try {
                    server.close(); // Zamknięcie serwera
                } catch (IOException e) {
                    e.printStackTrace(); // Obsługa błędów wejścia/wyjścia
                }
            }
        }
    }

    private static class ClientHandler implements Runnable {
        private final Socket clientSocket; // Deklaracja zmiennej Socket
        private SecurityUtils securityUtils; // Deklaracja zmiennej SecurityUtils
        private PublicKey clientPublicKey; // Deklaracja zmiennej PublicKey

        public ClientHandler(Socket socket) {
            this.clientSocket = socket; // Inicjalizacja zmiennej Socket
        }

        public void run() {
            PrintWriter out = null; // Deklaracja zmiennej PrintWriter
            BufferedReader in = null; // Deklaracja zmiennej BufferedReader

            try {
                // Inicjalizacja narzędzi kryptograficznych
                securityUtils = new SecurityUtils();
                System.out.println("Inicjalizacja zabezpieczeń dla klienta: " +
                        clientSocket.getInetAddress().getHostAddress());

                ObjectInputStream objIn = new ObjectInputStream(clientSocket.getInputStream()); // Inicjalizacja ObjectInputStream
                ObjectOutputStream objOut = new ObjectOutputStream(clientSocket.getOutputStream()); // Inicjalizacja ObjectOutputStream

                // Krok 1: Wymiana kluczy publicznych
                clientPublicKey = (PublicKey) objIn.readObject(); // Odczytanie klucza publicznego klienta
                securityUtils.setPartnerPublicKey(clientPublicKey); // Ustawienie klucza publicznego partnera
                System.out.println("Otrzymano klucz publiczny od klienta");

                objOut.writeObject(securityUtils.getPublicKey()); // Wysłanie klucza publicznego do klienta
                System.out.println("Wysłano klucz publiczny do klienta");

                // Krok 2: Uwierzytelnienie klienta
                byte[] challenge = securityUtils.generateChallenge(); // Generowanie wyzwania
                objOut.writeObject(challenge); // Wysłanie wyzwania do klienta
                System.out.println("Wysłano wyzwanie do klienta");

                byte[] clientResponse = (byte[]) objIn.readObject(); // Odczytanie odpowiedzi klienta
                boolean clientVerified = securityUtils.verifyChallenge(challenge, clientResponse, clientPublicKey); // Weryfikacja odpowiedzi klienta

                if (!clientVerified) {
                    throw new SecurityException("Nie udało się zweryfikować tożsamości klienta!"); // Rzucenie wyjątku w przypadku niepowodzenia weryfikacji
                }
                System.out.println("Zweryfikowano tożsamość klienta");

                // Krok 3: Uwierzytelnienie serwera
                byte[] clientChallenge = (byte[]) objIn.readObject(); // Odczytanie wyzwania od klienta
                byte[] serverResponse = securityUtils.signChallenge(clientChallenge); // Podpisanie wyzwania
                objOut.writeObject(serverResponse); // Wysłanie odpowiedzi na wyzwanie klienta
                System.out.println("Wysłano odpowiedź na wyzwanie klienta");

                // Krok 4: Wysłanie klucza AES (tylko jeśli uwierzytelnienie się powiodło)
                byte[] encryptedAESKey = securityUtils.encryptAESKey(clientPublicKey); // Szyfrowanie klucza AES
                objOut.writeObject(encryptedAESKey); // Wysłanie zaszyfrowanego klucza AES
                System.out.println("Wysłano zaszyfrowany klucz AES");

                out = new PrintWriter(clientSocket.getOutputStream(), true); // Inicjalizacja PrintWriter
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); // Inicjalizacja BufferedReader

                String line;
                while ((line = in.readLine()) != null) {
                    System.out.println("Otrzymano wiadomość: " + line);

                    String[] parts = securityUtils.decodeMessage(line); // Dekodowanie wiadomości
                    String message = parts[0]; // Odczytanie wiadomości
                    byte[] signature = Base64.getDecoder().decode(parts[1]); // Odczytanie podpisu

                    if (!securityUtils.verify(message, signature, clientPublicKey)) {
                        System.out.println("Ostrzeżenie: Nieprawidłowy podpis wiadomości!"); // Ostrzeżenie w przypadku nieprawidłowego podpisu
                        continue;
                    }

                    String[] splitted = message.split("#|:"); // Rozdzielenie wiadomości
                    String response = null; // Deklaracja zmiennej odpowiedzi

                    switch (splitted[1]) {
                        case "login": {
                            // Przekazanie wiadomości do serwera logowania
                            try (Socket loginSocket = new Socket("localhost", 2137);
                                 PrintWriter loginOut = new PrintWriter(loginSocket.getOutputStream(), true);
                                 BufferedReader loginIn = new BufferedReader(new InputStreamReader(loginSocket.getInputStream()))) {
                                loginOut.println(message); // Wysłanie wiadomości do serwera logowania
                                response = loginIn.readLine(); // Odczytanie odpowiedzi z serwera logowania
                                if (response != null) {
                                    byte[] responseSignature = securityUtils.sign(response); // Podpisanie odpowiedzi
                                    out.println(securityUtils.encodeMessage(response, responseSignature)); // Wysłanie zakodowanej odpowiedzi
                                }
                            }
                            break;
                        }
                        case "register": {
                            // Przekazanie wiadomości do serwera rejestracji
                            try (Socket registerSocket = new Socket("localhost", 2138);
                                 PrintWriter registerOut = new PrintWriter(registerSocket.getOutputStream(), true);
                                 BufferedReader registerIn = new BufferedReader(new InputStreamReader(registerSocket.getInputStream()))) {
                                registerOut.println(message); // Wysłanie wiadomości do serwera rejestracji
                                response = registerIn.readLine(); // Odczytanie odpowiedzi z serwera rejestracji
                                if (response != null) {
                                    byte[] responseSignature = securityUtils.sign(response); // Podpisanie odpowiedzi
                                    out.println(securityUtils.encodeMessage(response, responseSignature)); // Wysłanie zakodowanej odpowiedzi
                                }
                            }
                            break;
                        }
                        case "tablica": {
                            // Przekazanie wiadomości do serwera tablicy
                            try (Socket tablicaSocket = new Socket("localhost", 2139);
                                 PrintWriter tablicaOut = new PrintWriter(tablicaSocket.getOutputStream(), true);
                                 BufferedReader tablicaIn = new BufferedReader(new InputStreamReader(tablicaSocket.getInputStream()))) {
                                tablicaOut.println(message); // Wysłanie wiadomości do serwera tablicy
                                response = tablicaIn.readLine(); // Odczytanie odpowiedzi z serwera tablicy
                                if (response != null) {
                                    byte[] responseSignature = securityUtils.sign(response); // Podpisanie odpowiedzi
                                    out.println(securityUtils.encodeMessage(response, responseSignature)); // Wysłanie zakodowanej odpowiedzi
                                }
                            }
                            break;
                        }
                        case "chat": {
                            // Przekazanie wiadomości do serwera czatu
                            try (Socket chatSocket = new Socket("localhost", 2120);
                                 PrintWriter chatOut = new PrintWriter(chatSocket.getOutputStream(), true);
                                 BufferedReader chatIn = new BufferedReader(new InputStreamReader(chatSocket.getInputStream()))) {
                                chatOut.println(message); // Wysłanie wiadomości do serwera czatu
                                response = chatIn.readLine(); // Odczytanie odpowiedzi z serwera czatu
                                if (response != null) {
                                    byte[] responseSignature = securityUtils.sign(response); // Podpisanie odpowiedzi
                                    out.println(securityUtils.encodeMessage(response, responseSignature)); // Wysłanie zakodowanej odpowiedzi
                                }
                            }
                            break;
                        }
                        case "FTO": {
                            // Przekazanie wiadomości do serwera transferu plików (out)
                            try (Socket FTOSocket = new Socket("localhost", 3333);
                                 PrintWriter FTOOut = new PrintWriter(FTOSocket.getOutputStream(), true);
                                 BufferedReader FTOIn = new BufferedReader(new InputStreamReader(FTOSocket.getInputStream()))) {
                                String packetToSend = message; // Przygotowanie pakietu do wysłania
                                int packetNo = Integer.parseInt(message.split("#|:")[7]); // Odczytanie liczby pakietów
                                FTOOut.println(packetToSend); // Wysłanie pakietu

                                int packetsSended = 1; // Inicjalizacja licznika wysłanych pakietów
                                while (packetsSended < packetNo) {
                                    String nextPacket = in.readLine(); // Odczytanie kolejnego pakietu
                                    String[] nextParts = securityUtils.decodeMessage(nextPacket); // Dekodowanie kolejnego pakietu
                                    if (securityUtils.verify(nextParts[0], Base64.getDecoder().decode(nextParts[1]), clientPublicKey)) {
                                        FTOOut.println(nextParts[0]); // Wysłanie kolejnego pakietu
                                    }
                                    packetsSended++; // Zwiększenie licznika wysłanych pakietów
                                }

                                response = FTOIn.readLine(); // Odczytanie odpowiedzi z serwera transferu plików
                                if (response != null) {
                                    byte[] responseSignature = securityUtils.sign(response); // Podpisanie odpowiedzi
                                    out.println(securityUtils.encodeMessage(response, responseSignature)); // Wysłanie zakodowanej odpowiedzi
                                }
                            }
                            break;
                        }
                        case "FTI": {
                            // Przekazanie wiadomości do serwera transferu plików (in)
                            try (Socket FTISocket = new Socket("localhost", 9921);
                                 PrintWriter FTIOut = new PrintWriter(FTISocket.getOutputStream(), true);
                                 BufferedReader FTIIn = new BufferedReader(new InputStreamReader(FTISocket.getInputStream()))) {
                                FTIOut.println(message); // Wysłanie wiadomości do serwera transferu plików
                                String receivedPacket = FTIIn.readLine(); // Odczytanie pakietu z serwera transferu plików

                                if (receivedPacket != null) {
                                    byte[] responseSignature = securityUtils.sign(receivedPacket); // Podpisanie pakietu
                                    out.println(securityUtils.encodeMessage(receivedPacket, responseSignature)); // Wysłanie zakodowanego pakietu

                                    int packetNo = Integer.parseInt(receivedPacket.split("#|:")[5]); // Odczytanie liczby pakietów
                                    int packetsSended = 1; // Inicjalizacja licznika wysłanych pakietów

                                    while (packetsSended < packetNo) {
                                        receivedPacket = FTIIn.readLine(); // Odczytanie kolejnego pakietu
                                        responseSignature = securityUtils.sign(receivedPacket); // Podpisanie kolejnego pakietu
                                        out.println(securityUtils.encodeMessage(receivedPacket, responseSignature)); // Wysłanie zakodowanego pakietu
                                        packetsSended++; // Zwiększenie licznika wysłanych pakietów
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Błąd podczas obsługi klienta: " + e.getMessage()); // Obsługa błędów
                e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
            } finally {
                try {
                    if (out != null) {
                        out.close(); // Zamknięcie PrintWriter
                    }
                    if (in != null) {
                        in.close(); // Zamknięcie BufferedReader
                        clientSocket.close(); // Zamknięcie gniazda klienta
                    }
                } catch (IOException e) {
                    e.printStackTrace(); // Obsługa błędów wejścia/wyjścia
                }
                System.out.println("Zakończono połączenie z klientem: " +
                        clientSocket.getInetAddress().getHostAddress()); // Wyświetlenie informacji o zakończeniu połączenia
            }
        }
    }
}