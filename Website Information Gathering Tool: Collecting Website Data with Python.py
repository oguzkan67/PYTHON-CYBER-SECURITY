import socket
import geocoder
import ssl
import requests
import subprocess

# Belirtilen URL'in IP adresini çözmek için kullanıyoruz
def get_ip_address(url):
    try:
        ip_address = socket.gethostbyname(url)
        return ip_address
    except socket.gaierror:
        return None

# Verilen IP adresinin coğrafi olarak konumunu belirlemek için
def get_location(ip_address):
    location = geocoder.ip(ip_address)
    return location

# Belirtilen IP adresinin belirtilen port numarasını kontrol etmek için
def check_port(ip_address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Bağlantı zaman aşımı (saniye cinsinden)
    result = sock.connect_ex((ip_address, port))
    sock.close()
    return result == 0

# Sadece 80. portun açık olup olmadığını kontrol etmek için
def is_port_80_open(ip_address):
    return check_port(ip_address, 80)

# Belirtilen URL'e ait tüm IP adreslerini almak için
def get_all_ip_addresses(url):
    try:
        ip_addresses = socket.gethostbyname_ex(url)[-1]
        return ip_addresses
    except socket.gaierror:
        return []

# Belirtilen URL'nin Time to Live (TTL) değerini almak için
def get_ttl(url):
    try:
        ttl = socket.gethostbyname_ex(url)[-2]
        return ttl
    except socket.gaierror:
        return None

# Yerel IP adresini almak için
def get_local_ip():
    local_ip = socket.gethostbyname(socket.gethostname())
    return local_ip

# Belirtilen URL'e ait SSL sertifikasını almak için
def get_ssl_certificate(url):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=url) as s:
            s.connect((url, 443))
            cert = s.getpeercert()
        return cert
    except ssl.SSLError:
        return None

# Belirtilen URL'e ait HTTP başlıklarını almak için
def get_http_headers(url):
    try:
        response = requests.head(url)
        headers = response.headers
        return headers
    except requests.exceptions.RequestException:
        return None

# Belirtilen URL için ICMP ping yanıtını almak için
def get_ping_response(url):
    try:
        # port noktası 80'deki URL'nin IP adresine TCP bağlantısı kurmaya çalışıyoruz (genelde 80 ve 443 numaralı portlar bir web sunucusunun HTTP ve HTTPS isteklerini dinlediği ve yanıtladığı yerlerdir. ama siz istediğiniz gibi modifiye edebilirsiniz veya bütün portları tarayabilirsiniz)
        ip_address = get_ip_address(url)
        if ip_address:
            return "Connection successful"
        else:
            return "Failed to resolve IP address"
    except Exception as e:
        return f"Error: {e}"

# Host adını alma
def get_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return None

# Kendi IP adresini alma
def get_own_ip():
    try:
        own_ip = requests.get('https://api.ipify.org').text
        return own_ip
    except requests.exceptions.RequestException:
        return None

# DNS kayıtlarını alma
def get_dns_records(url):
    try:
        dns_records = socket.gethostbyname_ex(url)[-1]
        return dns_records
    except socket.gaierror:
        return []

# robots.txt dosyasını kontrol etme
def check_robots_txt(url):
    try:
        response = requests.get(url + "/robots.txt")
        return response.text
    except requests.exceptions.RequestException:
        return None

# SSL sertifikası bilgilerini alt alta yazdırma

def print_ssl_certificate(cert):
    print("SSL Certificate:")
    print(f"Subject: {cert.get('subject')}")
    print(f"Issuer: {cert.get('issuer')}")
    print(f"Version: {cert.get('version')}")
    print(f"Serial Number: {cert.get('serialNumber')}")
    print(f"Not Before: {cert.get('notBefore')}")
    print(f"Not After: {cert.get('notAfter')}")
    print("Subject Alternative Names:")
    for name in cert.get('subjectAltName', []):
        print(f"- {name[0]}: {name[1]}")
    print(f"OCSP: {cert.get('OCSP')}")
    print(f"CA Issuers: {cert.get('caIssuers')}")
    crl_distribution_points = cert.get('crlDistributionPoints', [])
    if crl_distribution_points:
        print("CRL Distribution Points:")
        for crl in crl_distribution_points:
            print(f"- {crl}")


# örnek kullanım şekli aşşağıdaki gibi
url = "turkcu.com"
ip_address = get_ip_address(url)
if ip_address:
    location = get_location(ip_address)
    port_80_open = is_port_80_open(ip_address)
    all_ip_addresses = get_all_ip_addresses(url)
    ttl = get_ttl(url)
    local_ip = get_local_ip()
    ssl_certificate = get_ssl_certificate(url)
    http_headers = get_http_headers(url)
    ping_response = get_ping_response(url)
    hostname = get_hostname(ip_address)
    own_ip = get_own_ip()
    dns_records = get_dns_records(url)
    robots_txt = check_robots_txt(url)

    print(f"IP Address: {ip_address}")
    print(f"Location: {location}")
    print(f"Is Port 80 Open: {port_80_open}")
    print(f"All IP Addresses: {all_ip_addresses}")
    print(f"TTL: {ttl}")
    print(f"Local IP Address: {local_ip}")
    print_ssl_certificate(ssl_certificate)
    print(f"HTTP Headers: {http_headers}")
    print(f"Ping Response: {ping_response}")
    print(f"Hostname: {hostname}")
    print(f"Own IP: {own_ip}")
    print(f"DNS Records: {dns_records}")
    print(f"Robots.txt: {robots_txt}")
else:
    print("Failed to resolve IP address for the given URL.")  # --> eğer bu çıktıyı alıyorsanız aşşağıdakilerden biri sebep oluyor olabilir kontrol edin
                                                                     #Geçersiz URL: URL'nin yanlış yazılmış veya eksik olması. mesela https://www.turkcu.com/ şeklinde yazmayın www.turkcu.com şeklinde yazın sadece turkcu.com yazsanızda olur
                                                                     #DNS Sorunu: DNS sunucusuna erişimde sorunlar olması.
                                                                     #Firewall Engeli: Güvenlik duvarı (firewall) tarafından URL'nin erişimine izin verilmemesi. 
  
