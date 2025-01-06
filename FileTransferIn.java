import java.io.*; // Importowanie klas do obsługi wejścia/wyjścia
import java.net.*; // Importowanie klas do obsługi sieci
import java.sql.SQLException; // Importowanie klasy do obsługi wyjątków SQL
import java.util.Base64; // Importowanie klasy do kodowania Base64
import java.util.StringJoiner; // Importowanie klasy do łączenia ciągów znaków

public class FileTransferIn {
    public static void main(String[] args) throws IOException, SQLException, ClassNotFoundException {
        // Tworzenie serwera nasłuchującego na porcie 9921
        ServerSocket ftiSocket = new ServerSocket(9921);
        System.out.println("Serwer transferu plików (in) uruchomiony na porcie 9921");
        System.out.println("Oczekiwanie na żądania w katalogu: C:\\Serwer_plikow\\");

        while (true) {
            try {
                // Akceptowanie połączenia od klienta
                Socket clientSocket = ftiSocket.accept();
                System.out.println("\n=== Nowe połączenie od: " + clientSocket.getInetAddress().getHostAddress() + " ===");
                PrintWriter FTIOut = new PrintWriter(clientSocket.getOutputStream(), true); // Inicjalizacja PrintWriter
                BufferedReader FTIIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); // Inicjalizacja BufferedReader

                // Odczytanie żądania od klienta
                String receivedPacket = FTIIn.readLine();
                String requestedFile = receivedPacket.split("#|:")[5]; // Odczytanie nazwy żądanego pliku
                System.out.println("Otrzymano żądanie pliku: " + requestedFile);

                // Ścieżka do pliku na serwerze
                String path = "C:\\Serwer_plikow\\" + requestedFile;
                File file = new File(path); // Inicjalizacja obiektu File
                StringJoiner newFTIpacket = new StringJoiner("#"); // Inicjalizacja StringJoiner

                if (!file.exists()) {
                    // Obsługa przypadku, gdy plik nie istnieje
                    System.out.println("BŁĄD: Plik nie istnieje: " + requestedFile);
                    newFTIpacket.add("status:NO");
                    newFTIpacket.add("filename:_");
                    newFTIpacket.add("packetsNo:0");
                    newFTIpacket.add("content:_");
                    FTIOut.println(newFTIpacket.toString()); // Wysłanie odpowiedzi do klienta
                } else {
                    // Obsługa przypadku, gdy plik istnieje
                    System.out.println("Znaleziono plik: " + file.getName());
                    System.out.println("Rozmiar pliku: " + file.length() + " bajtów");

                    long fileSize = file.length(); // Odczytanie rozmiaru pliku
                    int packetCount = (int) Math.ceil((double) fileSize / 1024); // Obliczenie liczby pakietów
                    System.out.println("Liczba pakietów do wysłania: " + packetCount);

                    byte[] buffer = new byte[1024]; // Inicjalizacja bufora
                    InputStream fileInputStream = new FileInputStream(file); // Inicjalizacja InputStream
                    int bytesRead; // Deklaracja zmiennej do przechowywania liczby odczytanych bajtów
                    int totalBytesSent = 0; // Inicjalizacja licznika wysłanych bajtów

                    for (int i = 0; i < packetCount; i++) {
                        // Odczytywanie danych z pliku i wysyłanie ich do klienta
                        bytesRead = fileInputStream.read(buffer); // Odczytanie danych do bufora
                        totalBytesSent += bytesRead; // Aktualizacja licznika wysłanych bajtów
                        byte[] packetToAdd = new byte[bytesRead]; // Inicjalizacja tablicy bajtów do wysłania
                        System.arraycopy(buffer, 0, packetToAdd, 0, bytesRead); // Kopiowanie danych do tablicy bajtów
                        newFTIpacket.add("status:OK");
                        newFTIpacket.add("filename:" + file.getName());
                        newFTIpacket.add("packetsNo:" + packetCount);
                        newFTIpacket.add("content:" + Base64.getEncoder().encodeToString(packetToAdd)); // Kodowanie danych do Base64

                        FTIOut.println(newFTIpacket.toString()); // Wysłanie pakietu do klienta
                        System.out.println("Wysłano pakiet " + (i + 1) + "/" + packetCount +
                                " (" + totalBytesSent + "/" + fileSize + " bajtów)");
                        newFTIpacket = new StringJoiner("#"); // Resetowanie StringJoiner
                    }
                    fileInputStream.close(); // Zamknięcie InputStream
                    System.out.println("Transfer zakończony pomyślnie");
                }
                System.out.println("=== Zakończono połączenie ===\n");
            } catch (Exception e) {
                // Obsługa błędów podczas transferu
                System.out.println("BŁĄD podczas transferu: " + e.getMessage());
                e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
            }
        }
    }
}