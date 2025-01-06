import java.io.*; // Importowanie klas do obsługi wejścia/wyjścia
import java.net.ServerSocket; // Importowanie klasy ServerSocket do obsługi gniazd serwera
import java.net.Socket; // Importowanie klasy Socket do obsługi gniazd klienta
import java.sql.SQLException; // Importowanie klasy do obsługi wyjątków SQL
import java.util.ArrayList; // Importowanie klasy ArrayList do przechowywania listy pakietów
import java.util.Base64; // Importowanie klasy do kodowania Base64

public class FileTransferOut {
    public static void main(String[] args) throws IOException, SQLException, ClassNotFoundException {
        // Tworzenie serwera nasłuchującego na porcie 3333
        ServerSocket FTOsocket = new ServerSocket(3333);
        System.out.println("Serwer transferu plików (out) uruchomiony na porcie 3333");
        System.out.println("Katalog docelowy: C:\\Serwer_plikow\\");

        while (true) {
            try {
                // Akceptowanie połączenia od klienta
                Socket clientSocket = FTOsocket.accept();
                System.out.println("\n=== Nowe połączenie od: " + clientSocket.getInetAddress().getHostAddress() + " ===");

                // Inicjalizacja strumieni do komunikacji z klientem
                PrintWriter ftoOut = new PrintWriter(clientSocket.getOutputStream(), true); // Inicjalizacja PrintWriter
                BufferedReader FTOIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); // Inicjalizacja BufferedReader
                ArrayList<String> packetsReceivedList = new ArrayList<String>(); // Inicjalizacja listy do przechowywania odebranych pakietów

                // Odczytanie pierwszego pakietu od klienta
                String receivedPacket = FTOIn.readLine(); // Odczytanie pakietu
                String[] initialPacketInfo = receivedPacket.split("#|:"); // Rozdzielenie informacji z pakietu
                String fileName = initialPacketInfo[5]; // Odczytanie nazwy pliku
                int packetNo = Integer.parseInt(initialPacketInfo[7]); // Odczytanie liczby pakietów

                System.out.println("Rozpoczęto odbieranie pliku: " + fileName);
                System.out.println("Oczekiwana liczba pakietów: " + packetNo);

                // Odbieranie kolejnych pakietów
                int packetsReceived = 1; // Inicjalizacja licznika odebranych pakietów
                System.out.println("Odebrano pakiet: 1/" + packetNo);

                while (packetsReceived < packetNo) {
                    packetsReceivedList.add(receivedPacket); // Dodanie pakietu do listy
                    receivedPacket = FTOIn.readLine(); // Odczytanie kolejnego pakietu
                    packetsReceived++; // Zwiększenie licznika odebranych pakietów
                    System.out.println("Odebrano pakiet: " + packetsReceived + "/" + packetNo);
                }
                if (packetNo == 1) {
                    packetsReceivedList.add(receivedPacket); // Dodanie pakietu do listy, jeśli jest tylko jeden pakiet
                }
                System.out.println("Odebrano wszystkie pakiety. Rozpoczynam składanie pliku...");

                // Składanie pliku z odebranych pakietów
                String[] splittedPacket; // Deklaracja tablicy do przechowywania rozdzielonych informacji z pakietu
                String newFileName = ""; // Inicjalizacja zmiennej do przechowywania nowej nazwy pliku
                ArrayList<byte[]> newFileContentList = new ArrayList<>(); // Inicjalizacja listy do przechowywania zawartości pliku
                long totalSize = 0; // Inicjalizacja zmiennej do przechowywania całkowitego rozmiaru pliku

                for (int i = 0; i < packetsReceivedList.size(); i++) {
                    splittedPacket = packetsReceivedList.get(i).split("#|:"); // Rozdzielenie informacji z pakietu
                    byte[] receivedContent = Base64.getDecoder().decode(splittedPacket[9]); // Dekodowanie zawartości pakietu
                    totalSize += receivedContent.length; // Aktualizacja całkowitego rozmiaru pliku
                    newFileContentList.add(receivedContent); // Dodanie zawartości pakietu do listy
                    if (i == 0) {
                        newFileName = splittedPacket[5]; // Ustawienie nazwy pliku na podstawie pierwszego pakietu
                    }
                }

                // Zapisanie pliku na serwerze
                String newPath = "C:\\Serwer_plikow\\" + newFileName; // Ścieżka do nowego pliku
                File file = new File(newPath); // Inicjalizacja obiektu File
                String response; // Deklaracja zmiennej do przechowywania odpowiedzi
                boolean isExisting = file.exists(); // Sprawdzenie, czy plik już istnieje

                if (newFileName.equals("")) {
                    response = "status:NO"; // Ustawienie odpowiedzi na "NO" w przypadku pustej nazwy pliku
                    System.out.println("BŁĄD: Otrzymano pustą nazwę pliku");
                } else if (isExisting) {
                    response = "status:NO"; // Ustawienie odpowiedzi na "NO" w przypadku, gdy plik już istnieje
                    System.out.println("BŁĄD: Plik już istnieje w lokalizacji: " + newPath);
                } else {
                    try (OutputStream outputStream = new FileOutputStream(file)) { // Inicjalizacja OutputStream do zapisu pliku
                        for (byte[] content : newFileContentList) {
                            outputStream.write(content); // Zapisanie zawartości do pliku
                        }
                        response = "status:OK"; // Ustawienie odpowiedzi na "OK" w przypadku pomyślnego zapisu pliku
                        System.out.println("Sukces: Zapisano plik " + newFileName);
                        System.out.println("Lokalizacja: " + newPath);
                        System.out.println("Rozmiar: " + totalSize + " bajtów");
                    } catch (IOException e) {
                        response = "status:NO"; // Ustawienie odpowiedzi na "NO" w przypadku błędu zapisu pliku
                        System.out.println("BŁĄD podczas zapisywania pliku: " + e.getMessage());
                        e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
                    }
                }

                // Wysłanie odpowiedzi do klienta
                ftoOut.println(response); // Wysłanie odpowiedzi do klienta
                System.out.println("=== Zakończono połączenie ===\n");
            } catch (Exception e) {
                // Obsługa błędów podczas obsługi połączenia
                System.out.println("BŁĄD podczas obsługi połączenia: " + e.getMessage());
                e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
            }
        }
    }
}