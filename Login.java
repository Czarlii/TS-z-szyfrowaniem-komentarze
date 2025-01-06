import java.io.*; // Importowanie klas do obsługi wejścia/wyjścia
import java.net.*; // Importowanie klas do obsługi sieci
import java.sql.*; // Importowanie klas do obsługi baz danych
import java.security.NoSuchAlgorithmException; // Importowanie klasy do obsługi wyjątków związanych z brakiem algorytmu

public class Login {
    private static SecurityUtils securityUtils; // Deklaracja zmiennej SecurityUtils

    public static void main(String[] args) throws IOException, SQLException, ClassNotFoundException, NoSuchAlgorithmException {
        // Tworzenie serwera nasłuchującego na porcie 2137
        ServerSocket loginSocket = new ServerSocket(2137);
        securityUtils = new SecurityUtils(); // Inicjalizacja SecurityUtils
        System.out.println("Serwer logowania uruchomiony na porcie 2137");

        while (true) {
            try {
                // Akceptowanie połączenia od klienta
                Socket clientSocket = loginSocket.accept();
                PrintWriter loginOut = new PrintWriter(clientSocket.getOutputStream(), true); // Inicjalizacja PrintWriter
                BufferedReader loginIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); // Inicjalizacja BufferedReader

                // Odczytanie zakodowanej wiadomości od klienta
                String encodedMessage = loginIn.readLine();
                String[] parts = encodedMessage.split("#|:"); // Rozdzielenie wiadomości na części

                // Login i hasło są już w formie niezaszyfrowanej, bo Server.java je rozszyfrował
                String login = parts[3]; // Odczytanie loginu
                String haslo = parts[5]; // Odczytanie hasła
                String odpowiedz; // Deklaracja zmiennej odpowiedzi

                // Połączenie z bazą danych i weryfikacja użytkownika
                try (Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/ts", "root", "karol1")) {
                    Class.forName("com.mysql.cj.jdbc.Driver"); // Załadowanie sterownika bazy danych
                    PreparedStatement statement = con.prepareStatement("select * from users where login=? and haslo=?"); // Przygotowanie zapytania SQL
                    statement.setString(1, login); // Ustawienie loginu w zapytaniu
                    statement.setString(2, haslo); // Ustawienie hasła w zapytaniu
                    ResultSet result = statement.executeQuery(); // Wykonanie zapytania

                    // Sprawdzenie, czy użytkownik istnieje w bazie danych
                    if (result.next()) {
                        odpowiedz = "status:OK"; // Ustawienie odpowiedzi na "OK" w przypadku udanego logowania
                        System.out.println("Udane logowanie dla: " + login);
                    } else {
                        odpowiedz = "status:NO"; // Ustawienie odpowiedzi na "NO" w przypadku nieudanego logowania
                        System.out.println("Nieudane logowanie dla: " + login);
                    }
                } catch (Exception e) {
                    e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
                    odpowiedz = "status:NO"; // Ustawienie odpowiedzi na "NO" w przypadku błędu
                }

                // Wysłanie odpowiedzi do klienta
                loginOut.println(odpowiedz);
            } catch (Exception e) {
                e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
            }
        }
    }
}