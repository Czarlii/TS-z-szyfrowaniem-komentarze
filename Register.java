import java.io.*; // Importowanie klas do obsługi wejścia/wyjścia
import java.net.*; // Importowanie klas do obsługi sieci
import java.sql.*; // Importowanie klas do obsługi baz danych

public class Register {
    public static void main(String[] args) throws IOException, SQLException, ClassNotFoundException {
        // Tworzenie serwera nasłuchującego na porcie 2138
        ServerSocket registerSocket = new ServerSocket(2138);
        System.out.println("Serwer rejestracji uruchomiony na porcie 2138");

        while (true) {
            try {
                // Akceptowanie połączenia od klienta
                Socket clientSocket = registerSocket.accept();
                PrintWriter registerOut = new PrintWriter(clientSocket.getOutputStream(), true); // Inicjalizacja PrintWriter
                BufferedReader registerIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); // Inicjalizacja BufferedReader

                // Odczytanie wiadomości rejestracyjnej od klienta
                String message = registerIn.readLine();
                System.out.println("Otrzymano żądanie rejestracji: " + message);
                String[] odebrane = message.split("#|:"); // Rozdzielenie wiadomości na części
                String odpowiedz; // Deklaracja zmiennej odpowiedzi

                // Połączenie z bazą danych i weryfikacja użytkownika
                try (Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/ts", "root", "karol1")) {
                    Class.forName("com.mysql.cj.jdbc.Driver"); // Załadowanie sterownika bazy danych
                    PreparedStatement checkStmt = con.prepareStatement("select * from users where login=?"); // Przygotowanie zapytania SQL do sprawdzenia użytkownika
                    checkStmt.setString(1, odebrane[3]); // Ustawienie loginu w zapytaniu
                    ResultSet result = checkStmt.executeQuery(); // Wykonanie zapytania

                    // Sprawdzenie, czy użytkownik już istnieje
                    if (!result.next()) {
                        // Rejestracja nowego użytkownika
                        PreparedStatement insertStmt = con.prepareStatement("INSERT INTO users (login,haslo) VALUES (?,?)"); // Przygotowanie zapytania SQL do rejestracji użytkownika
                        insertStmt.setString(1, odebrane[3]); // Ustawienie loginu w zapytaniu
                        insertStmt.setString(2, odebrane[5]); // Ustawienie hasła w zapytaniu
                        insertStmt.executeUpdate(); // Wykonanie zapytania
                        odpowiedz = "status:OK"; // Ustawienie odpowiedzi na "OK" w przypadku pomyślnej rejestracji
                        System.out.println("Zarejestrowano nowego użytkownika: " + odebrane[3]);
                    } else {
                        // Użytkownik już istnieje
                        odpowiedz = "status:NO"; // Ustawienie odpowiedzi na "NO" w przypadku, gdy użytkownik już istnieje
                        System.out.println("Próba rejestracji istniejącego użytkownika: " + odebrane[3]);
                    }
                } catch (Exception e) {
                    e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
                    odpowiedz = "status:NO"; // Ustawienie odpowiedzi na "NO" w przypadku błędu
                }

                // Wysłanie odpowiedzi do klienta
                registerOut.println(odpowiedz);
            } catch (Exception e) {
                e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
            }
        }
    }
}