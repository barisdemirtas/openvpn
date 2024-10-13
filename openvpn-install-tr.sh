#!/bin/bash
# Baris Demirtas https://www.barisdemirtas.com.tr
# https://github.com/barisdemirtas/openvpn/blob/main/openvpn-install-tr.sh
# Copyright (c) 2024 BarNeo. 
# Thanks Nyr

# Debian kullanicilarini "sh" ile degil "bash" ile calistirmaya yonlendirme
if readlink /proc/$$/exe | grep -q "dash"; then
    echo 'Bu yukleyici "bash" ile calistirilmalidir, "sh" ile degil.'
    exit
fi

# Standart girdiyi yok say. Bir satirlik bir komuttan calistirildiginda gerekebilir.
read -N 999999 -t 0.001

# Isletim sistemini tespit et
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
    os="centos"
    os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
    os="fedora"
    os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    group_name="nobody"
else
    echo "Bu yukleyici, desteklenmeyen bir dagitim uzerinde calisiyor. Desteklenen dagitimlar: Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS ve Fedora."
    exit
fi

# Ubuntu surumu kontrolu
if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
    echo "Bu yukleyiciyi kullanmak icin Ubuntu 22.04 veya daha yeni bir surum gereklidir. Bu Ubuntu surumu cok eski ve desteklenmiyor."
    exit
fi

# Debian surumu kontrolu
if [[ "$os" == "debian" ]]; then
    if grep -q '/sid' /etc/debian_version; then
        echo "Debian Testing ve Debian Unstable bu yukleyici tarafindan desteklenmiyor."
        exit
    fi
    if [[ "$os_version" -lt 11 ]]; then
        echo "Bu yukleyiciyi kullanmak icin Debian 11 veya daha yeni bir surum gereklidir. Bu Debian surumu cok eski ve desteklenmiyor."
        exit
    fi
fi

# CentOS surumu kontrolu
if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
    os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
    echo "$os_name 9 veya uzeri gereklidir. Bu $os_name surumu cok eski ve desteklenmiyor."
    exit
fi

# $PATH degiskeni sbin dizinlerini icermiyorsa uyari ver
if ! grep -q sbin <<< "$PATH"; then
    echo '$PATH sbin icermiyor. "su -" komutunu kullanmayi deneyin.'
    exit
fi

# Betigin super kullanici ayricaliklariyla calistirilip calistirilmadigini kontrol et
if [[ "$EUID" -ne 0 ]]; then
    echo "Bu yukleyici super kullanici ayricaliklariyla calistirilmalidir."
    exit
fi

# TUN cihazinin olup olmadigini kontrol et
if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
    echo "Sistemde TUN cihazi mevcut degil. Bu yukleyiciyi calistirmadan once TUN etkinlestirilmelidir."
    exit
fi

# Yeni bir istemci olusturma islemi
new_client () {
    # Ozel client.ovpn dosyasini olusturur
    {
    cat /etc/openvpn/server/client-common.txt
    echo "<ca>"
    cat /etc/openvpn/server/easy-rsa/pki/ca.crt
    echo "</ca>"
    echo "<cert>"
    sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
    echo "</cert>"
    echo "<key>"
    cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
    echo "</key>"
    echo "<tls-crypt>"
    sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
    echo "</tls-crypt>"
    } > ~"$client".ovpn
}

# OpenVPN sunucu yapilandirmasinin olup olmadigini kontrol et
if [[ ! -e /etc/openvpn/server/server.conf ]]; then
    # Debian minimal kurulumlarinda wget veya curl olmadiginda uyari ver
    if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
        echo "Wget bu yukleyiciyi kullanmak icin gereklidir."
        read -n1 -r -p "Wget yuklemek ve devam etmek icin bir tusa basin..."
        apt-get update
        apt-get install -y wget
    fi
    clear
    echo 'OpenVPN road warrior yukleyicisine hos geldiniz!'
    # Sistem tek bir IPv4 adresine sahipse otomatik olarak secilir. Aksi takdirde kullaniciya sorulur
    if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
        echo
        echo "Hangi IPv4 adresi kullanilacak?"
        ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
        read -p "IPv4 adresi [1]: " ip_number
        until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
            echo "$ip_number: gecersiz secim."
            read -p "IPv4 adresi [1]: " ip_number
        done
        [[ -z "$ip_number" ]] && ip_number="1"
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
    fi
    # Eger $ip ozel bir IP adresiyse, sunucu NAT arkasinda olmalidir
    if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
        echo
        echo "Bu sunucu NAT arkasinda. Genel IPv4 adresi veya ana bilgisayar adi nedir?"
        # Genel IP'yi al ve grep ile temizle
        get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
        read -p "Genel IPv4 adresi / ana bilgisayar adi [$get_public_ip]: " public_ip
        # Eger checkip servisi kullanilamiyorsa ve kullanici giris yapmadiysa tekrar sor
        until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
            echo "Gecersiz giris."
            read -p "Genel IPv4 adresi / Ana Bilgisayar Adi: " public_ip
        done
        [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
    fi
    # Sistem tek bir IPv6 adresine sahipse otomatik olarak secilir
    if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
    fi
    # Sistem birden fazla IPv6 adresine sahipse kullaniciya secim yapmasi sorulur
    if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
        number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
        echo
        echo "Hangi IPv6 adresi kullanilacak?"
        ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
        read -p "IPv6 adresi [1]: " ip6_number
        until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
            echo "$ip6_number: gecersiz secim."
            read -p "IPv6 adresi [1]: " ip6_number
        done
        [[ -z "$ip6_number" ]] && ip6_number="1"
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
    fi
    echo
    echo "OpenVPN hangi protokolu kullanmali?"
    echo "   1) UDP (onerilen)"
    echo "   2) TCP"
    read -p "Protokol [1]: " protocol
    until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
        echo "$protocol: gecersiz secim."
        read -p "Protokol [1]: " protocol
    done
    case "$protocol" in
        1|"") 
        protocol=udp
        ;;
        2) 
        protocol=tcp
        ;;
esac
    echo
    echo "OpenVPN hangi portu dinlemeli?"
    read -p "Port [1194]: " port
    until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
        echo "$port: gecersiz port."
        read -p "Port [1194]: " port
    done
    [[ -z "$port" ]] && port="1194"
    echo
    echo "Istemciler icin bir DNS sunucu secin:"
    echo "   1) Mevcut sistem cozuculer"
    echo "   2) Google"
    echo "   3) 1.1.1.1"
    echo "   4) OpenDNS"
    echo "   5) Quad9"
    echo "   6) AdGuard"
    read -p "DNS sunucu [1]: " dns
    until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
        echo "$dns: gecersiz secim."
        read -p "DNS sunucu [1]: " dns
    done
    echo
    echo "Ilk istemci icin bir isim girin:"
    read -p "Isim [client]: " unsanitized_client
    # Cakismalari onlemek icin sinirli karakter kumesine izin ver
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
    [[ -z "$client" ]] && client="client"
    echo
    echo "OpenVPN kurulumu baslamaya hazir."
    # firewalld veya iptables yüklü degilse bir guvenlik duvari yukleyin
    if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
        if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
            firewall="firewalld"
            echo "firewalld, yonlendirme tablolarini yonetmek icin gereklidir ve kurulacaktir."
        elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
            firewall="iptables"
        fi
    fi
    read -n1 -r -p "Devam etmek icin bir tusa basin... ( barisdemirtas.com.tr )"
    # Bir konteyner icinde calisiyorsa LimitNPROC'u devre disi birak
    if systemd-detect-virt -cq; then
        mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
        echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
    fi
    if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
        apt-get update
        apt-get install -y --no-install-recommends openvpn openssl ca-certificates $firewall
    elif [[ "$os" = "centos" ]]; then
        dnf install -y epel-release
        dnf install -y openvpn openssl ca-certificates tar $firewall
    else
        # OS Fedora olmalidir
        dnf install -y openvpn openssl ca-certificates tar $firewall
    fi
    # Eger firewalld yeni kurulduysa etkinlestir
    if [[ "$firewall" == "firewalld" ]]; then
        systemctl enable --now firewalld.service
    fi
    # easy-rsa alin
    easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.1/EasyRSA-3.2.1.tgz'
    mkdir -p /etc/openvpn/server/easy-rsa/
    { wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
    chown -R root:root /etc/openvpn/server/easy-rsa/
    cd /etc/openvpn/server/easy-rsa/
    # PKI olusturun, CA ve sunucu ve istemci sertifikalarini ayarlayin
    ./easyrsa --batch init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa --batch --days=3650 build-server-full server nopass
    ./easyrsa --batch --days=3650 build-client-full "$client" nopass
    ./easyrsa --batch --days=3650 gen-crl
    # Gerekli dosyalari tasiyin
    cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
    # CRL, her istemci baglantisinda okunur
    chown nobody:"$group_name" /etc/openvpn/server/crl.pem
    # Dizin +x olmadan OpenVPN CRL dosyasinda stat() calistiramaz
    chmod o+x /etc/openvpn/server/
    # tls-crypt anahtarini olusturun
    openvpn --genkey secret /etc/openvpn/server/tc.key
    # DH parametreleri dosyasini olusturun
    echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
    # server.conf olustur
    echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.9.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
    # IPv6
    if [[ -z "$ip6" ]]; then
        echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
    else
        echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
        echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
    fi
    echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
    # DNS
    case "$dns" in
        1|"")
            if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
                resolv_conf="/etc/resolv.conf"
            else
                resolv_conf="/run/systemd/resolve/resolv.conf"
            fi
            grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
                echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
            done
        ;;
        2)
            echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
        ;;
        3)
            echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
        ;;
        4)
            echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
        ;;
        5)
            echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
        ;;
        6)
            echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
        ;;
esac
    echo 'push "block-outside-dns"' >> /etc/openvpn/server/server.conf
    echo "keepalive 10 120
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
    if [[ "$protocol" = "udp" ]]; then
        echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
    fi
    # Sistemde net.ipv4.ip_forward etkinlestirme
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
    # Yeniden baslatmayi beklemeden etkinlestir
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if [[ -n "$ip6" ]]; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$port"/"$protocol"
        firewall-cmd --zone=trusted --add-source=10.9.0.0/24
        firewall-cmd --permanent --add-port="$port"/"$protocol"
        firewall-cmd --permanent --zone=trusted --add-source=10.9.0.0/24
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to "$ip"
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to "$ip"
        if [[ -n "$ip6" ]]; then
            firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
            firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
            firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
            firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
        fi
    else
        # Kalici iptables kurallari olusturmak icin bir servis olustur
        iptables_path=$(command -v iptables)
        ip6tables_path=$(command -v ip6tables)
        if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
            iptables_path=$(command -v iptables-legacy)
            ip6tables_path=$(command -v ip6tables-legacy)
        fi
        echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.9.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.9.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
        if [[ -n "$ip6" ]]; then
            echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
        fi
        echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
        systemctl enable --now openvpn-iptables.service
    fi
    # Eger SELinux etkinse ve ozel bir port secildiyse bu gerekli
    if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
        if ! hash semanage 2>/dev/null; then
                dnf install -y policycoreutils-python-utils
        fi
        semanage port -a -t openvpn_port_t -p "$protocol" "$port"
    fi
    # Sunucu NAT arkasindaysa dogru IP adresini kullan
    [[ -n "$public_ip" ]] && ip="$public_ip"
    echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
ignore-unknown-option block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
    systemctl enable --now openvpn-server@server.service
    new_client
    echo
    echo "Tamamlandi!"
    echo
    echo "Istemci yapilandirmasi burada mevcut:" ~"$client.ovpn"
    echo "Yeni istemciler eklemek icin bu betigi tekrar calistirabilirsiniz."
else
    clear
    echo "OpenVPN zaten kurulu."
    echo
    echo "Bir secenek belirleyin:"
    echo "   1) Yeni bir kullanici ekleyin"
    echo "   2) Mevcut bir kullanici iptal edin"
    echo "   3) OpenVPN'i kaldirin"
    echo "   4) Cikis"
    read -p "Secenek: " option
    until [[ "$option" =~ ^[1-4]$ ]]; do
        echo "$option: gecersiz secim."
        read -p "Secenek: " option
    done
    case "$option" in
        1)
            echo
            echo "Istemci icin bir isim girin:"
            read -p "Isim: " unsanitized_client
            client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
            while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
                echo "$client: gecersiz isim."
                read -p "Isim: " unsanitized_client
                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
            done
            cd /etc/openvpn/server/easy-rsa/
            ./easyrsa --batch --days=3650 build-client-full "$client" nopass
            new_client
            echo
            echo "$client eklendi. Yapilandirma burada mevcut:" ~"$client.ovpn"
            exit
        ;;
        2)
            number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
            if [[ "$number_of_clients" = 0 ]]; then
                echo
                echo "Mevcut istemci yok!"
                exit
            fi
            echo
            echo "Iptal edilecek istemciyi secin:"
            tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
            read -p "Istemci: " client_number
            until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                echo "$client_number: gecersiz secim."
                read -p "Istemci: " client_number
            done
            client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
            echo
            read -p "$client iptal edilsin mi? [e/H]: " revoke
            until [[ "$revoke" =~ ^[eEhH]*$ ]]; do
                echo "$revoke: gecersiz secim."
                read -p "$client iptal edilsin mi? [e/H]: " revoke
            done
            if [[ "$revoke" =~ ^[eE]$ ]]; then
                cd /etc/openvpn/server/easy-rsa/
                ./easyrsa --batch revoke "$client"
                ./easyrsa --batch --days=3650 gen-crl
                rm -f /etc/openvpn/server/crl.pem
                cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
                chown nobody:"$group_name" /etc/openvpn/server/crl.pem
                echo
                echo "$client iptal edildi!"
            else
                echo
                echo "$client iptali iptal edildi!"
            fi
            exit
        ;;
        3)
            echo
            read -p "OpenVPN kaldirilsin mi? [e/H]: " remove
            until [[ "$remove" =~ ^[eEhH]*$ ]]; do
                echo "$remove: gecersiz secim."
                read -p "OpenVPN kaldirilsin mi? [e/H]: " remove
            done
            if [[ "$remove" =~ ^[eE]$ ]]; then
                port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
                protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
                if systemctl is-active --quiet firewalld.service; then
                    ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.9.0.0/24 "'!'" -d 10.9.0.0/24' | grep -oE '[^ ]+$')
                    firewall-cmd --remove-port="$port"/"$protocol"
                    firewall-cmd --zone=trusted --remove-source=10.9.0.0/24
                    firewall-cmd --permanent --remove-port="$port"/"$protocol"
                    firewall-cmd --permanent --zone=trusted --remove-source=10.9.0.0/24
                    firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to "$ip"
                    firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to "$ip"
                    if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
                        ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 "'!'" -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
                        firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
                        firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
                        firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
                        firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
                    fi
                else
                    systemctl disable --now openvpn-iptables.service
                    rm -f /etc/systemd/system/openvpn-iptables.service
                fi
                if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
                    semanage port -d -t openvpn_port_t -p "$protocol" "$port"
                fi
                systemctl disable --now openvpn-server@server.service
                rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
                rm -f /etc/sysctl.d/99-openvpn-forward.conf
                if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
                    rm -rf /etc/openvpn/server
                    apt-get remove --purge -y openvpn
                else
                    dnf remove -y openvpn
                    rm -rf /etc/openvpn/server
                fi
                echo
                echo "OpenVPN kaldirildi!"
            else
                echo
                echo "OpenVPN kaldirma islemi iptal edildi!"
            fi
            exit
        ;;
        4)
            exit
        ;;
esac
fi
