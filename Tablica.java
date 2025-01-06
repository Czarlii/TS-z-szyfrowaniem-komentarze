import java.io.*; // Importowanie klas do obsługi wejścia/wyjścia
import java.net.*; // Importowanie klas do obsługi sieci
import java.sql.*; // Importowanie klas do obsługi baz danych
import java.security.NoSuchAlgorithmException; // Importowanie klasy do obsługi wyjątków związanych z brakiem algorytmu

public class Tablica {
    private static SecurityUtils securityUtils; // Deklaracja zmiennej SecurityUtils

    public static void main(String[] args) throws IOException, SQLException, ClassNotFoundException, NoSuchAlgorithmException {
        // Tworzenie serwera nasłuchującego na porcie 2139
        ServerSocket tablicaSocket = new ServerSocket(2139);
        securityUtils = new SecurityUtils(); // Inicjalizacja SecurityUtils
        System.out.println("Serwer tablicy uruchomiony na porcie 2139");

        while (true) {
            try {
                // Akceptowanie połączenia od klienta
                Socket clientSocket = tablicaSocket.accept();
                PrintWriter tablicaOut = new PrintWriter(clientSocket.getOutputStream(), true); // Inicjalizacja PrintWriter
                String odpowiedz = "status:OK#tresc:#"; // Inicjalizacja zmiennej odpowiedzi

                // Połączenie z bazą danych i pobranie ostatnich 10 wpisów z tablicy
                try (Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/ts", "root", "karol1")) {
                    Class.forName("com.mysql.cj.jdbc.Driver"); // Załadowanie sterownika bazy danych
                    Statement statement = con.createStatement(); // Utworzenie obiektu Statement
                    String loginTworzacego; // Deklaracja zmiennej do przechowywania loginu twórcy posta
                    String trescPosta; // Deklaracja zmiennej do przechowywania treści posta
                    ResultSet result = statement.executeQuery("select * from tablica order by id desc LIMIT 10"); // Wykonanie zapytania SQL
                    int count = 0; // Inicjalizacja licznika wpisów
                    while (result.next()) {
                        count++; // Zwiększenie licznika wpisów
                        loginTworzacego = result.getString("autor"); // Odczytanie loginu twórcy posta
                        trescPosta = result.getString("tresc"); // Odczytanie treści posta
                        odpowiedz += loginTworzacego + ":" + trescPosta + "#"; // Dodanie wpisu do odpowiedzi
                    }
                    System.out.println("Pobrano " + count + " wpisów z tablicy");
                } catch (Exception e) {
                    e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
                    odpowiedz = "status:NO"; // Ustawienie odpowiedzi na "NO" w przypadku błędu
                }

                // Wysłanie odpowiedzi do klienta
                tablicaOut.println(odpowiedz);
            } catch (Exception e) {
                e.printStackTrace(); // Wyświetlenie stosu wywołań błędu
            }
        }
    }
}