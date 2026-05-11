# Настройка ca

## Базовые настройки после установки операционной системы

Установка сетевых параметров, имени компьютера, включение в домен

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 172.1.1.5 -PrefixLength 24 -DefaultGateway 172.1.1.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 172.1.1.2
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -Name "DisabledComponents" -Value 0xffffffff -PropertyType "DWord"
# GLVK ключ для Windows Server 2022 Standard
slmgr.vbs -ipk VDYBN-27WPP-V4HQT-9VMD4-VMK7H
# Если надо конвертировать windows server 2022 в standart
# dism /online /set-edition:ServerStandard /productkey:VDYBN-27WPP-V4HQT-9VMD4-VMK7H /accepteula
Add-Computer -NewName "CA" -DomainName "domain.lab" -OUPath "OU=Domain Servers,DC=domain,DC=lab" -Credential "Администратор@domain.lab" -Restart -Force
```

## Настройка Центра Сертификации

#### Установка CA без веб-портала (рекомендуемый вариант)
#### ВАЖНО! Root-CA ставлю отдельно на linux машину с последующим перемещением OVA на флеш накопитель для предотвращения компрометации корневого сертификата (-CAType EnterpriseSubordinateCA вместо CAType EnterpriseRootCA)

#### Установка CA без веб-портала (использовать не буду т.к. выдаю сертификаты на сетевое оборудование)

```powershell
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools -Source "D:\sources\sxs"
Install-ADcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName "domain.lab-Issuing-CA" -CADistinguishedNameSuffix "DC=domain,DC=lab" -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5 -DatabaseDirectory "C:\windows\system32\certLog" -LogDirectory "C:\windows\system32\CertLog" -Force
```

#### Установка CA с веб-порталом

```powershell
Install-WindowsFeature ADCS-Cert-Authority,ADCS-Web-Enrollment,ADCS-Cert-Enrollment-Web-Service,ADCS-Cert-Enrollment-Policy-Web-Service,ADCS-Device-Enrollment-Service,ADCS-Online-Responder -IncludeManagementTools -Source "D:\sources\sxs"
Install-ADcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName "domain.lab-Issuing-CA" -CADistinguishedNameSuffix "DC=domain,DC=lab" -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5 -DatabaseDirectory "C:\windows\system32\certLog" -LogDirectory "C:\windows\system32\CertLog" -Force
# Настройка веб-портала
Install-AdcsWebEnrollment -Force
Get-ChildItem Cert:\LocalMachine\My\ # берем тут отпечаток
New-IISSiteBinding -Name "Default Web Site" -BindingInformation "*:443:" -CertificateThumbPrint "ОТПЕЧАТОК_СЕРТИФИКАТА" -CertStoreLocation "Cert:\LocalMachine\My" -Protocol https
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Location "Default Web Site/CertSrv" -Filter "system.webServer/security/access" -Name "sslFlags" -Value "Ssl"
```

#### Настройка CA 

Разрешить выдачу сертификатов на 5 лет

```powershell
Set-ItemProperty -Path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CertSvc\Configuration\domain.lab-Issuing-CA" -Name "ValidityPeriodUnits" -Value 5
```

Включить SAN атрибуты (для того чтобы в запросе через веб-портал можно было запрашивать дополнительное имя субъекта, например: `san:dns=web.domain.lab&dns=www.web.domain.lab`)

```powershell
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Eсли требуется публиковать на веб-портале шаблоны сертификатов версии 3 и выше, надо в `ADSIedit` установить параметр **`msPKI-Template-Schema-Version`** по пути `Configuration -> Services -> Public Key Services -> Certificate Templates` для нужного шаблона равным **`2`**

#### Настройка публикации списков отзыва

Устанавливаем веб-сервер

```powershell
Install-WindowsFeature Web-Server -IncludeManagementTools
```

Создаем алиас (CNAME) в DNS, например `pki.domain.lab`

```powershell
Add-DnsServerResourceRecordCName -Name "pki" -HostNameAlias "ca.domain.lab" -ZoneName "domain.lab"
```
**Настройка IIS**

Список отзыва сертификатов корневого ЦС будет доступен через `https://pki.domain.lab/pki`.

В настоящее время нет виртуального каталога PKI, поэтому его необходимо создать.

`Диспетчер служб IIS` -> `Default Web Site` -> `Добавить виртуальный каталог` -> В псевдоним пишем `pki`. В физическом пути пишем `C:\pki`

Включам анонимный доступ к виртуальной директории 
`Редактировать разрешения` -> `Безопасность` -> `Изменить` -> `Добавить...` -> `АНОНИМНЫЙ ВХОД; Все` 
**Разрешения на папку ТОЛЬКО ЧТЕНИЕ и выполоне**

Выбираем `Фильтрация запросов` -> `Расширения имен файлов` -> `Изменить параметры` -> `Разрешить двойное преобразование`

Перезапускаем IIS.

**Настройка расширений CDP и AIA**

Переходим в свойства CA, вкладка расширения

**Настройка CDP**

**Удалем** строки:
```
file://\\<ServerDNSName>\CertEnroll\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl
http://<ServerDNSName>/CertEnroll/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl
ldap:///CN=<CATruncatedName><CRLNameSuffix>,CN=<ServerShortName>
```

**Добавляем** следующие строки:
```
http://pki.domain.lab/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl
```
Выбираем 
- `Включить в CRLs. Клиенты используют данные для поиска в размещениях Delta CRL`
- `Включить в CDP-расширения выданных сертификатов`

```
file://C:\pki\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl
```
Выбираем 
- `Опубликовать CRL по данному адресу`
- `Публикация разностных CRLs по адресу`

**Настройка AIA**

**Удалем** строки:
```
ldap:///CN=<CATruncatedName>,CN=AIA,CN=Public Key Services
http://<ServerDNSName>/CertEnroll/<ServerDNSName>_<CaName><CertificateName>.crt
file://\\<ServerDNSName>\CertEnroll\<ServerDNSName><CaName><CertificateName>.crt
```

**Добавляем** следующие строки:
```
http://pki.domain.lab/pki/<ServerDNSName>_<CaName><CertificateName>.crt
```
Выбираем 
- `Включать в AIA-расширение выданных сертификатов`
- `Публиковать сертификат по этому адресу`

**Копириуем списки отзыва сертификатов**

```
certutil -crl
copy C:\Windows\system32\certsrv\certenroll\*.crt C:\pki
copy C:\Windows\system32\certsrv\certenroll\*.crl C:\pki
pkiview.msc
```

#### Пример запроса сертификата OpenSSL

```
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -addext "basicConstraints = critical, CA:FALSE" -addext "keyUsage = critical, digitalSignature, keyEncipherment" -addext "extendedKeyUsage = serverAuth, clientAuth" -addext "subjectAltName = DNS:server.domain.lab"
```

#### Просмотр информации о запросе на выдачу сертификата

```
certutil -dump request.req
```


#### Выдача сертификатов по файлам CSR (*.req)

- Без указания шаблона и SAN
```
certreq -submit
```
- C указанием шаблона (SAN в запросе *.req)
```
certreq -submit -attrib "CertificateTemplate:ИМЯ_ШАБЛОНА"
```
- C указанием шаблона и SAN
```
certreq -submit -attrib "CertificateTemplate:ИМЯ_ШАБЛОНА\nsan:dns=АДРЕС_СЕРВЕРА&ipaddress=IP_СЕРВЕРА"
```

- Для proxmox
```
certreq -submit -attrib "CertificateTemplate:WebServer`nsan:dns=pve.domain.lab&ipaddress=192.168.254.201" C:\csr\pve.csr
certreq -retrieve *** C:\certs\pve.crt
```

- Для ILO/iDRAC на будующее для Intel SR5600
```
certreq -submit -attrib "CertificateTemplate:WebServer`nsan:dns=ilo.domain.lab&ipaddress=192.168.254.200" C:\csr\ilo.csr
certreq -retrieve *** C:\certs\ilo.crt
```

- Для GW по нескольким
```
certreq -submit -attrib "CertificateTemplate:WebServer`nsan:dns=GW.domain.lab&ipaddress=192.168.254.1&ipaddress=172.1.1.1&ipaddress=10.10.0.100" C:\csr\gw.csr
certreq -retrieve *** C:\certs\gw.crt
```
- Для R1 по нескольким ip
```
certreq -submit -attrib "CertificateTemplate:WebServer`nsan:dns=R1.domain.lab&ipaddress=192.168.254.210&ipaddress=164.11.15.210&ipaddress=10.10.0.210" C:\csr\switch.csr
certreq -retrieve *** C:\certs\switch.crt
```
