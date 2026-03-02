# Настройка SecServerBD
### Не забывайте разделять ЦУ и сервер безопасности
## Базовые настройки после установки операционной системы

Установка сетевых параметров, имени компьютера

```powershell
Rename-Computer SecServer
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 172.1.1.4 -PrefixLength 24 -DefaultGateway 172.1.1.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 127.0.0.1
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -Name "DisabledComponents" -Value 0xffffffff -PropertyType "DWord"
# GLVK ключ для Windows Server 2022 Standard
slmgr.vbs -ipk VDYBN-27WPP-V4HQT-9VMD4-VMK7H
# Если надо конвертировать windows server 2022 standart eva в standart 
# dism /online /set-edition:ServerStandard /productkey:VDYBN-27WPP-V4HQT-9VMD4-VMK7H /accepteula
Restart-Computer -Confirm
```
## Установка MSQL
При установке не забудьте выставить настройки сортировки - Cyrillic_General_CI_AS, они должны подкинуться сами если ОС русифицированна, но лучше проверьте.
Режим проверки подлинности выставляйте смешанный и дайте доступ к базе хотя бы одному администратору из под Windows.
