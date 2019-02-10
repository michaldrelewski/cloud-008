Przykład wykorzystania kontenerów  Docker jako serwisów usług w sieciach Data Center.



Celem projektu jest wdrożenie usług DNS, DHCP, SFTP,  NTP przy użyciu kontenerów Docker oraz monitorowanie tych usług wraz z graficznym przedstawieniem statusu.  Zasadą projektu będzie podział zasobów między kontenerami usług, znajdującymi się na maszynie wirtualnej z systemem operacyjnym CentOS 7. Stacją do testów w.w. usług oraz monitoringu będzie maszyna wirtualna z systemem Fedora Workstation w wersji 29.  

CentOS jest dystrybucją Linux opartą na Red Hat Enterprise, mający być z nią w pełni kompatybilny oraz wspierający architekturę Intel x86. Aktualną stabilną wersją jest wersja oznaczona jako 7.0. Pakiety zarządzane są przez Yum. Wybrałem CentOS ze względu na wsparcie dla pakietów RPM, osobiste preferencje oraz doświadczenie z RHEL. 

Fedora 29 Workstation - Rodzina dystrybucji Linux, sponsorowaną przez firmę Red Hat. Fundacja stawia na innowacyjność, wszechstronność oraz otwartość. Fedora posiada bardzo obszerną dokumentację, dodatkowo jest prawdopodobnie najbardziej przyjaznym użytkownikowi systemem operacyjnym z rodziny systemów Linux.

Docker 17.12.1-ce - platforma do tworzenia, wdrażania i uruchamiania aplikacji rozproszonych w kontenerach. Co ważne, Docker jest open source, czyli każdy może dopasować platformę do swoich wymagań, jeżeli potrzebuje funkcjonalności niedostępnych w standardowym pakiecie. Wybór platformy Docker podyktował również wybór systemów operacyjnych używanych w projekcie. Wersje CentOS starsze niż 7 nie są wspierane przez dostawcę, podobnie w przypadku Fedora.

Obrazy usług zostanę pobrane z http://hub.docker.com/, ponieważ znajdują się tam oficjalne obrazy opublikowane przez Docker oraz obrazy przez nich certyfikowane i ze zweryfikowaną treścią. //Linki dodam później//



Czym są kontenery?

Technologia kontenerów jest alternatywną metodą wirtualizacji, gdzie zamiast uruchamiać kolejny/kolejne systemy operacyjne na hoście uruchamiamy kontener dzielący jądro z hostem. Ze względu na współdzielenie zasobów z hostem, na przykład bibliotek systemowych, kontenery są dużo lżejsze, dzięki czemu startują dużo szybciej. VM w porównaniu do kontenerów są o rząd większe. W przypadku kontenerów można utworzyć przenośne, spójne środowisko operacyjne do programowania, testowania i wdrażania. 

![Containers vs. VMs](https://www.sdxcentral.com/wp-content/uploads/2016/01/containers-versus-virtual-machines-docker-inc-rightscale.jpg)



Usługi wdrażane przy pomocy kontenerów.

**DNS** - system nazw domenowych(Domain Name System), to usługa oraz protokół komunikacyjny obsługujący rozproszoną bazę danych adresów sieciowych. Tłumaczy nazwę mnemoniczną na odpowiadający jej adres IP. 

Format komunikatu DNS: 

| NAGŁÓWEK – (Header)                                          |
| ------------------------------------------------------------ |
| ZAPYTANIE – (Question) do serwera nazw                       |
| ODPOWIEDŹ – (Answer) zawiera rekordy będące odpowiedzią      |
| ZWIERZCHNOŚĆ – (Authority) wskazuje serwery zwierzchnie dla domeny |
| DODATKOWA – (Additional) sekcja informacji dodatkowych       |

 Forma nagłówka, który określa rolę całego komunikatu: 

Sekcja nagłówka występuje zawsze. W sekcji zapytania zawsze znajduje się jedno zapytanie zawierające nazwę domenową, żądany typ danych i klasę (IN). Sekcja odpowiedzi zawiera rekordy zasobów stanowiące odpowiedź na pytanie. 

 

| 0       | 1      | 2    | 3    | 4    | 5    | 6    | 7     | 8    | 9    | 10   | 11   | 12   | 13   | 14   | 15   |
| ------- | ------ | ---- | ---- | ---- | ---- | ---- | ----- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| ID      |        |      |      |      |      |      |       |      |      |      |      |      |      |      |      |
| QR      | OPCODE | AA   | TC   | RD   | RA   | Z    | RCODE |      |      |      |      |      |      |      |      |
| QDCOUNT |        |      |      |      |      |      |       |      |      |      |      |      |      |      |      |
| ANCOUNT |        |      |      |      |      |      |       |      |      |      |      |      |      |      |      |
| NSCOUNT |        |      |      |      |      |      |       |      |      |      |      |      |      |      |      |
| ARCOUNT |        |      |      |      |      |      |       |      |      |      |      |      |      |      |      |

 

- ID [16 bitów] – (IDentifier) – identyfikator tworzony przez program wysyłający zapytanie; serwer przepisuje ten identyfikator do swojej odpowiedzi, dzięki czemu możliwe jest jednoznaczne powiązanie zapytania i odpowiedzi
- QR [1 bit] – (Query or Response) – określa, czy komunikat jest zapytaniem (0) czy odpowiedzią (1)
- OPCODE [4 bity] – określa rodzaj zapytania wysyłanego od klienta, jest przypisywany przez serwer do odpowiedzi. Wartości: 
  - 0 – QUERY – standardowe zapytanie,
  - 1 – IQUERY – zapytanie zwrotne,
  - 2 – STATUS – pytanie o stan serwera,
  - 3-15 – zarezerwowane do przyszłego użytku.
- AA [1 bit] – (Authoritative Answer) – oznacza, że odpowiedź jest autorytatywna.
- TC [1 bit] – (TrunCation) – oznacza, że odpowiedź nie zmieściła się w jednym pakiecie UDP i została obcięta.
- RD [1 bit] – (Recursion Desired) – oznacza, że klient żąda rekurencji – pole to jest kopiowane do odpowiedzi
- RA [1 bit] – (Recursion Available) – bit oznaczający, że serwer obsługuje zapytania rekurencyjne
- Z [3 bity] – zarezerwowane do przyszłego wykorzystania. Pole powinno być wyzerowane.
- RCODE [4 bity] – (Response CODE) kod odpowiedzi. Przyjmuje wartości: 
  - 0 – brak błędu,
  - 1 – błąd formatu – serwer nie potrafił zinterpretować zapytania,
  - 2 – błąd serwera – wewnętrzny błąd serwera,
  - 3 – błąd nazwy – nazwa domenowa podana w zapytaniu nie istnieje,
  - 4 – nie zaimplementowano – serwer nie obsługuje typu otrzymanego zapytania,
  - 5 – odrzucono – serwer odmawia wykonania określonej operacji, np. transferu strefy,
  - 6-15 – zarezerwowane do przyszłego użytku.
- QDCOUNT [16 bitów] – określa liczbę wpisów w sekcji zapytania
- ANCOUNT [16 bitów] – określa liczbę rekordów zasobów w sekcji odpowiedzi
- NSCOUNT [16 bitów] – określa liczbę rekordów serwera w sekcji zwierzchności
- ARCOUNT [16 bitów] – określa liczbę rekordów zasobów w sekcji dodatkowej

Najważniejsze typy rekordów DNS oraz ich znaczenie: 

 **rekord A** lub **rekord adresu IPv4 (ang. address record)** mapuje nazwę domeny DNS na jej 32-bitowy adres IPv4

**rekord AAAA** lub **rekord adresu IPv6 (ang. IPv6 address record)** mapuje nazwę domeny DNS na jej 128-bitowy adres IPv6.

**rekord CNAME** lub **rekord nazwy kanonicznej (ang. canonical name record)** ustanawia alias nazwy domeny. Wszystkie wpisy DNS oraz subdomeny są poprawne także dla aliasu.

**rekord MX** lub **rekord wymiany poczty (ang. mail exchange record)** mapuje nazwę domeny DNS na nazwę serwera poczty oraz jego priorytet, który określa kolejność wraz ze wzrostem wartości.

**rekord PTR** lub **rekord wskaźnika (ang. pointer record)** mapuje adres [Pv4 lub IPv6 na nazwę kanoniczną hosta. Określenie rekordu PTR dla nazwy hosta (ang. *hostname*) w domenie `in-addr.arpa` (IPv4), bądź `ip6.arpa` (IPv6), który odpowiada adresowi IP, pozwala na implementację odwrotnej translacji adresów DNS (ang. *reverse DNS lookup*, revDNS)

**rekord NS** lub **rekord serwera nazw (ang. name server record)** mapuje nazwę domenową na listę serwerów DNS dla tej domeny.

**rekord SOA** lub **rekord adresu startowego uwierzytelnienia (ang. start of authority record)** ustala serwer DNS dostarczający *autorytatywne* informacje o domenie internetowej, łącznie z jej parametrami (np. TTL).

**rekord SRV** lub **rekord usługi (ang. service record)** pozwala na zawarcie dodatkowych informacji dotyczących lokalizacji danej usługi, którą udostępnia serwer wskazywany przez adres DNS.

**rekord TXT** – rekord ten pozwala dołączyć dowolny tekst do rekordu DNS.



**DHCP**(Dynamic Host Configuration Protocol) - protokół dynamicznego konfigurowania hostów. Umożliwia hostom uzyskanie od serwera danych konfiguracyjnych, np. adresu IP hosta, adresu IP bramy sieciowej, adresu serwera DNS, maski podsieci. 

![img](https://help.ubnt.com/hc/article_attachments/115010035527/dhcp-offer-overview.png)

Podobnie jak w przypadku uzgadniania sieci, oferta DHCP jest podsumowywana w czterech krokach, w których klient wysyła broadcast, a serwer unicast. 

Komunikaty DHCP:

DHCPDISCOVER – zlokalizowanie serwerów

DHCPOFFER – przesyłanie parametrów

DHCPREQUEST – żądanie przydzielenia używanych parametrów

DHCPACK – potwierdzenie przydziału parametrów

DHCPNAK – odmowa przydziału parametrów

DHCPDECLINE – wskazanie że adres sieciowy jest już używany

DHCPRELEASE – zwolnienie adresu

DHCPINFORM – żądanie przydziału parametrów (bez adresu IP)

**SFTP** (SSH File Transfer Protocol) - Protokół komunikacyjny typu klient-serwer, który umożliwia przesyłanie plików przez sieć TCP/IP. Ułatwia dostęp do danych i ich przesyłanie przez strumień danych Secure Shell(SSH). Wspiera pełną funkcjonalność zabezpieczeń i uwierzytelniania SSH. Zapewnie wszystkie funkcje oferowane przez FTP i FTP/S, ale bezpieczniej i bardziej niezawodnie. Chroni również przed atakami typu "man-in-the-middle" oraz chroni integralność danych za pomocą szyfrowania i funkcji mieszania kryptograficznego.



**NTP** (Network Time Protocol) - protokół synchronizacji czasu. Umożliwia precyzyjną synchronizację czasu pomiędzy komputerami.  Wzorcowy czas może pochodzić bezpośrednio z zegarów atomowoych, bądź pośrednio ze specjalizowanych serwerów czasu. Protokół ten jest uznany za światowy standard synchronizacji czasu. 

Opis komunikatu NTP

| LI                   | VN   | Mode | Stratum | Poll interval | Precision |
| -------------------- | ---- | ---- | ------- | ------------- | --------- |
| Root Delay           |      |      |         |               |           |
| Root Dispersion      |      |      |         |               |           |
| Reference Identifier |      |      |         |               |           |
| Reference Timestamp  |      |      |         |               |           |
| Originate Timestamp  |      |      |         |               |           |
| Receive Timestamp    |      |      |         |               |           |
| Transmit Timestamp   |      |      |         |               |           |
| Authenticator        |      |      |         |               |           |

 **LI** – wskaźnik sekund przestępnych

**VN** – (Version Number) numer wersji protokołu

**Mode** – tryb pracy (m.in. tryb klienta, serwera, symetryczny pasywny, symetryczny aktywny, rozgłoszeniowy – serwer czasu okresowo rozsyła do wszystkich podległych klientów komunikat o czasie)

**Stratum** – warstwa, w której funkcjonuje komputer będący nadawcą komunikatu

**Poll interval** – okres pomiędzy kolejnymi aktualizacjami czasu

**Precision** – określenie dokładności zegara komputera wysyłającego dany komunikat

**Root Delay** – opóźnienie pomiędzy nadawcą a serwerem warstwy 1

**Root Dispersion** – maksymalny błąd pomiędzy zegarem lokalnym a serwera warstwy 1

**Reference Identifier** – identyfikator źródła czasu, względem którego następuje synchronizacja

**Reference Timestamp** – pole zawierające pomocnicze informacje o czasie poprzedniej synchronizacji

**Originate Timestamp** – pole zawierające czas wysłania żądania przez klienta

**Receive Timestamp** – czas odebrania komunikatu od klienta (ustawiane przez serwer odpowiadający na żądanie klienta)

**Transmit Timestamp** – czas wysłania odpowiedzi do klienta (ustawiane przez serwer odpowiadający na żądanie klienta)

**Authenticator** – informacje uwierzytelniające zarówno klienta, jak i serwer czasu



