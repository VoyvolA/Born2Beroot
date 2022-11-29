# Born2Beroot
# Born2Beroot

👨‍💻Sanal makina nasıl çalışır ?

Bir sanal makina bilgisayardan ayrılan ram-depolama alanı gibi değerlerı alır ve bunu sadece o sanal makinada kullanılanıma uygun olacak şekilde ayarlar.

👨‍💻Seçtiğin işletim sistemi nedir ?

Debian

Debian ile CentOS arasındaki farklar nelerdir ?

CentOS rpm paket yöneticisine sahiptir Debian ise apt-get paket yöneticisine sahiptir.

CentOS repoları daha az sıklıkla güncellenirken Debian repoları daha sık bir şekilde güncellenir

CentOS Red hat Linux tarafından desteklenir ve daha kararlı bir dağıtımdır bunun sebebi paket güncellemeleri daha az sıklıkla gerçekleşir.

C: Kurulumu ve yapılandırması CentOS'tan daha kolaydır

👨‍💻Sanal makinelerin amacı nedir ?

tek bir fiziksel bilgisayarda çalışarak çoklu işletim sistemi kullanma olanağı sağlar. Böylece fiziksel alan, zaman, yönetim, donanım ve yazılım masraflarından tasarruf sağlar.

👨‍💻Aptitude ve apt arasındaki farklar ve APParmor nedir ?

Aptitude APT'ın kullanıcı arabirimidir. Yazılım paketlerini listelemeye, onları seçip kurmaya ve kaldırmaya yarar. APT debian tabanlı sistemlerin paket yöneticisidir APT ile yazılım kurma, yazılım kaldırma, sistemi güncelleme, çekirdeği derleme gibi işlemleri terminal üzerinden gerçekleştirebilirsiniz.

AppArmor, sistem yöneticisinin programların yeteneklerini program başına farklı tanımlarla kısıtlamasına olanak tanıyan bir Linux çekirdek güvenlik modülüdür.AppArmor, savunmasız süreçleri kilitler, bu süreçlerdeki güvenlik açıklarının neden olabileceği hasarı sınırlar.

A: Aptitude, üst düzey bir paket yöneticisidir, APT ise başkaları tarafından kullanılabilen daha düşük düzeyli bir paket yöneticisidir.

👨‍💻UFW service başlatılmış mı diye kontrol et

sudo ufw status

👨‍💻SSH service başlatılmış mı diye kontrol et

sudo systemctl status ssh

👨‍💻Sistemin Debian mı CentOS'mu olup olmadığını kontrol et

hostnamectl

👨‍💻kullanıcı sudo ya ekli mi diye kontrol et

getent group sudo

Öncelikle yeni bir kullanıcı oluştur, şifreyi kurallara uygun olarak koy, bu kuralları nasıl oluşturduğunu açıkla.

Sudo adduser new_username

sudo vim /etc/pam.d/common-password

minlen=10

şifrenin minimum uzunluğu

👨‍💻retry=3 maximum 3 deneme hakki

👨‍💻lcredit=-1 en az 1 küçük harf

👨‍💻ucredit=-1 en az 1 büyük harf

👨‍💻dcredit=-1 en az 1 sayı

👨‍💻maxrepeat=3 en fazla 3 arka arka aynı karakter

👨‍💻usercheck=0 şifre kullanıcı adını içeriyor mu diye kontrol

👨‍💻difok=7 yeni şifre eski şifreden minimum 7 karakter farklı olmalı

enforce_for_root root kullanıcıları için de aynı şeylerin geçerli olduğunu belirtir

👨‍💻Evaluating adında bir grup oluştur, bu gruba oluşturduğun yeni kullanıcı ata ve kontrol et.

sudo groupadd evaluating

sudo adduser evaluating_user

getent group evaluating

şifre kurallarının avantajları

bir şifreye büyük, küçük harf, rakam, özel karakterler eklemek o şifrenin bulunmasını zorlaştırır.

hostname'in <ogrenci ismi>42 formatına uygun olup olmadığını kontrol et

hostnamectl

hostnameyi degistir ve reboot at

hostnamectl set-hostname new_hostname

sudo reboot

sudo nun yüklü olup olmadığını kontrol etme

sudo —version

sudo'nun amacı sudoers gibi alt pluginlerle şifre süresini belirleme şifre gereksinimi belirleme gibi şeyleri ayarlamak ve bazı önemli komutları sadece root yetkisine sahip kişilerin kullanabilmesi.

/var/log/sudo klasörünün olup olmadığına bak ve içinde en azında bir dosyanın olduğunu teyit et

sudo visudo

👨‍💻UFW çalışıyor mu kontrol et

sudo ufw status

👨‍💻UFW nin ne olduğunu açıkla

Karmaşık Olmayan Güvenlik Duvarı (Uncomplicated Firewall), kullanımı kolay olacak şekilde tasarlanmış bir netfilter güvenlik duvarını yönetmek için kullanılan bir programdır.

👨‍💻UFW'nin aktif kurallarını listele, 4242 portu listede olmalı

sudo ufw status

👨‍💻8080 portu için yeni bir kural ekle, kontrol et yeni kuralı sil

sudo ufw allow 8080

sudo ufw status numbered sudo ufw delete number

👨‍💻Basitçe SSH nedir anlat

SSH, veya Secure Shell, kullanıcılara sunucularını internet üzerinden kontrol etmesini ve düzenlemesini sağlayan uzak yönetim protokolüdür.

SSH servisinin sadece 4242 portunu kullandığından emin ol sudo grep Port /etc/ssh/sshd_config

Yeni oluşturulan kullanıcı ile SSH kullanarak bağlantı kurunuz

ssh your_username@127.0.0.1 -p 4242

👨‍💻crontab'ı kontrol et ve ne olduğunu açıkla

sudo crontab -u root -e

- *monitoring.sh dosyasını kontrol et**

👨‍💻uname: belirli sistem bilgilerini yazdırır -a: all- bütün bilgileri yazdırır

sort: Tekst dosyalarının satırlarını sınıflandırır

wc (word count) komutu dosyada bulunan satır sayısını, kelime sayısını ve karakter sayısını çıktı olarak verir.

- l = line

Uniq :tekrarlanan satırları rapor et veya atla

Free:Sistemdeki boş ve kullanılan bellek miktarını görüntüleme -m: megabytes

Awk: desen tarama ve işleme dili

Df: dosya sistemi disk alanı kullanımını rapor et

Her DOSYA'nın bulunduğu dosya sistemi veya varsayılan olarak tüm dosya sistemleri hakkındaki bilgileri gösterin.

Bg: boyutları yazdırmadan önce SIZE'a göre ölçeklendirin.

👨‍💻Xargs: standart girdiden komut satırları oluşturun ve yürütün

👨‍💻Lsblk: blok cihazları listeler

👨‍💻Journalctl: sistem içeriğini sorgular

👨‍💻Top : linux görevlerini gösteriyor

[Sorular](https://www.notion.so/Sorular-40a893399d884b6180da4626e88c516a)

[kod brifingi](https://www.notion.so/kod-brifingi-a43ed5b33560464aa3feadb1b3a55f54)
