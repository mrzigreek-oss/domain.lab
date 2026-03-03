# Настройка SecServerBD
# Важно напомнить! Создайте для виртуалки два диска, в одном будет ваш диск C на второй будем сохранять архивы базы. В идеале производитель рекомендует 150Гб СВОБОДНОГО ПРОСТРАНСТВА.
### Не забывайте разделять ЦУ и сервер безопасности
## Базовые настройки после установки операционной системы

Установка сетевых параметров, имени компьютера

```powershell
Rename-Computer SecServerBD
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 172.1.1.16 -PrefixLength 24 -DefaultGateway 172.1.1.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 172.1.1.2
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

## Выдача прав локального администратора SecServerBD
На контроллере домена выдать пользователю *rootts* **(Дубликат, описано на DC1)** локального администратора для виртуальной машины.
```powershell
Invoke-Command -ComputerName "SecServerBd" -ScriptBlock {
    Get-LocalGroupMember -Group (Get-LocalGroup -SID "S-1-5-32-544").Name | Select-Object Name
}
```
### На этапе установки перепроверьте куда ставите сервер безопасности, если ставите для юнита выбирайте юнит, если ставите главный сервер ставите в корень домена. 
###### На следующем шаге выставите для архивов отдельную папку или диск.
<img width="494" height="58" alt="image" src="https://github.com/user-attachments/assets/51e39b26-df33-49ab-a40d-0572982772c2" />
далее следуем гайду

### *Важная пометка* При первом развёртывании системы безопасности пользователь который устанавливает пакет ОБЯЗАН состоять в группах администраторов домане и админисраторов леса безопасности. 

### *Важная пометка 2* Как отключить пользователям доступ к локальному центру управления. 
```powershell
Переходим по путиC:\Program Files\InfoCode\Trust Cover\Client\Components\Control Center, находим нашу Medusa.exe, заходим в свойства отключаем наследование и выставляем дискредиционку на админов, удаляя при этом группу ВСЕ
```
<img width="1170" height="623" alt="image" src="https://github.com/user-attachments/assets/9f440184-791c-4091-8b2e-4049223bf61e" />
