import java.io.*; // Importowanie klas do obsługi wejścia/wyjścia
import java.net.*; // Importowanie klas do obsługi sieci
import java.sql.*; // Importowanie klas do obsługi baz danych
import java.security.NoSuchAlgorithmException; // Importowanie klasy do obsługi wyjątków związanych z brakiem algorytmu

public class Chat {
    private static SecurityUtils securityUtils; // Deklaracja zmiennej SecurityUtils

    public static void main(String[] args) throws IOException, SQLException, ClassNotFoundException, NoSuchAlgorithmException {
        // Tworzenie serwera nasłuchującego na porcie 2120
        ServerSocket chatSocket = new ServerSocket(2120);
        securityUtils = new SecurityUtils(); // Inicjalizacja SecurityUtils
        System.out.println("Serwer czatu uruchomiony na porcie 2120");

        while (true) {
            try {
                // Akceptowanie połączenia od klienta
                Socket clientSocket = chatSocket.accept();
                PrintWriter chatOut = new PrintWriter(clientSocket.getOutputStream(), true); // Inicjalizacja PrintWriter
                BufferedReader chatIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); // Inicjalizacja BufferedReader

                // Odczytanie wiadomości od klienta
                String message = chatIn.readLine();
                System.out.println("Otrzymano wiadomość: " + message);

                // Wiadomość jest już odszyfrowana przez Server.java
                String[] parts = message.split("#|:"); // Rozdzielenie wiadomości na części
                String odpowiedz; // Deklaracja zmiennej odpowiedzi

                // Połączenie z bazą danych i dodanie wpisu do tablicy
                try (Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/ts", "root", "karol1")) {
                    Class.forName("com.mysql.cj.jdbc.Driver"); // Załadowanie sterownika bazy danych
                    PreparedStatement insertStmt = con.prepareStatement("INSERT INTO tablica (autor, tresc) VALUES (?, ?)"); // Przygotowanie zapytania SQL do dodania wpisu
                    insertStmt.setString(1, parts[3]); // Ustawienie autora w zapytaniu
                    insertStmt.setString(2, parts[5]); // Ustawienie treści w zapytaniu
                    insertStmt.executeUpdate(); // Wykonanie zapytania

                    // Sprawdzenie liczby wpisów i usunięcie najstarszego, jeśli jest ich więcej niż 10
                    Statement countStmt = con.createStatement(); // Utworzenie obiektu Statement
                    ResultSet result = countStmt.executeQuery("SELECT COUNT(*) FROM tablica"); // Wykonanie zapytania SQL do zliczenia wpisów
                    result.next(); // Przejście do pierwszego wyniku
                    int count = result.getInt(1); // Odczytanie liczby wpisów

                    if (count > 10) {
                        Statement deleteStmt = con.createStatement(); // Utworzenie obiektu Statement do usunięcia wpisu
                        deleteStmt.executeUpdate("DELETE FROM tablica WHERE ID IN (SELECT ID FROM (SELECT ID FROM tablica ORDER BY ID ASC LIMIT 1) AS t)"); // Wykonanie zapytania SQL do usunięcia najstarszego wpisu
                    }

                    odpowiedz = "status:OK"; // Ustawienie odpowiedzi na "OK" w przypadku pomyślnego dodania wpisu
                    System.out.println("Dodano wpis od użytkownika: " + parts[3]);
                } catch (Exception e) {
                    e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
                    odpowiedz = "status:NO"; // Ustawienie odpowiedzi na "NO" w przypadku błędu
                }

                // Wysłanie odpowiedzi do klienta
                chatOut.println(odpowiedz);
            } catch (Exception e) {
                e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
            }
        }
    }
}