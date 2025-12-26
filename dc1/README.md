# Настройка dc1

## Базовые настройки после установки операционной системы

Установка сетевых параметров, имени компьютера

```powershell
Rename-Computer DC1
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.69.1 -PrefixLength 24 -DefaultGateway 192.168.69.254
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 127.0.0.1
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -Name "DisabledComponents" -Value 0xffffffff -PropertyType "DWord"
# В новых редакциях активация не сработает, разворачиваем КМС сервер на линухе https://github.com/Wind4/vlmcsd
Restart-Computer -Confirm
```

## Настройка AD

#### Установка компонентов AD

```powershell
$password = "Password1234@!" | ConvertTo-SecureString -AsPlainText -Force
Install-WindowsFeature -Name AD-Domain-Services,RSAT-ADCS-Mgmt -IncludeAllSubFeature -IncludeManagementTools
# После создания домена автоматическая перезагрузка
Install-ADDSForest -DomainName "domain.lab" -InstallDns -SafeModeAdministratorPassword $password -Force
```

#### Настройка DNS, установка и настройка DHCP

```powershell
# Создание зоны обратного просмотра DNS
Add-DnsServerPrimaryZone -NetworkID "172.1.1.0/24" -ReplicationScope Forest
# DHCP
Install-WindowsFeature -Name DHCP -IncludeManagementTools
netsh dhcp add securitygroups
Restart-Service DHCPServer
Add-DhcpServerInDC "dc1.domain.lab" 172.1.1.2
Set-ItemProperty -Path "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12" -Name "ConfigurationState" -Value 2
Add-DhcpServerv4Scope -Name "domain.lab" -StartRange 172.1.1.10 -EndRange 172.1.1.50 -SubnetMask 255.255.255.0 -Description "domain.lab" -State "Active"
Set-DhcpServerv4OptionValue -ScopeId 172.1.1.0 -DnsDomain "domain.lab" -Router 172.1.1.1 -DnsServer 172.1.1.2
```

#### Создание OU в AD

```powershell
$domainCN = "DC=domain,DC=lab"
# Создание OU
New-ADOrganizationalUnit -Name "Domain Users" -Path $domainCN
New-ADOrganizationalUnit -Name "Domain Computers" -Path $domainCN
New-ADOrganizationalUnit -Name "Domain Servers" -Path $domainCN
# перенаправление новых ПК в OU Domain Computers
redircmp "OU=Domain Computers,$domainCN"
```

#### Копируем папку `GPO` на `dc1` и настраиваем групповые политики

```powershell
# Установка переменных
$gpoDir = "C:\GPO"
$domain = "domain.lab"
$domainCN = "DC=domain,DC=lab"
$sysvol = "C:\Windows\SYSVOL\sysvol\$domain"
```

#### Копирование административных шаблонов и модулей PowerShell
```powershell
Copy-Item "$gpoDir\PolicyDefinitions" -Destination "$sysvol\Policies\" -Recurse
Copy-Item "$gpoDir\PSModules\*" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Force
```

#; Создание WMI фильтров

### Для обновлённых серверов сборки после 2023 года в моём случае - 21H2 20348.4529 дополнительно ввести команды:
#### Разрешаем запуск локальных скриптов без подписи
```powershell
Set-ExecutionPolicy RemoteSigned -Force
#### Снимаем блокировку со всех файлов в папке модулей:
Get-ChildItem -Path "C:\Program Files\WindowsPowerShell\Modules" -Recurse | Unblock-File
Import-Module -Name GPWmiFilter
New-GPWmiFilter -Name 'Windows 10/11' -Expression 'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%" AND ProductType = "1"'
New-GPWmiFilter -Name 'Windows Servers (2019-2025)' -Expression 'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%" AND ProductType <> 1
```

#### Импорт GPO MSFT
```powershell
Import-GPO -BackupId "{DD304A7D-15A7-42B7-AB52-2338F4ECE2C7}" -Path "$gpoDir\MSFT" -TargetName "MSFT Windows 10 21H2 - Computer" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{4B6589C2-0290-4764-8058-9825B56B4169}" -Path "$gpoDir\MSFT" -TargetName "MSFT Windows 10 21H2 - User" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{E4ACFC12-94D6-4565-91B7-8A37C4CB0FC4}" -Path "$gpoDir\MSFT" -TargetName "MSFT Windows Server 2022 - Domain Controller" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{AAC7C960-51D3-4BEE-89BD-7FB10361AA16}" -Path "$gpoDir\MSFT" -TargetName "MSFT Windows Server 2022 - Domain Security" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{20FAD6FB-7C6D-496E-801C-0434769847FF}" -Path "$gpoDir\MSFT" -TargetName "MSFT Windows Server 2022 - Member Server" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{02B7D8F9-E7A7-470B-B16B-FED032FFD9CB}" -Path "$gpoDir\MSFT" -TargetName "MSFT SMB v1 client for pre-Win8.1/2012R2" -CreateIfNeeded | Out-Null
```

#### Импорт GPO домена
```powershell
Import-GPO -BackupId "{58818EE0-E49D-4B43-BAEC-EC7E7F2FEB68}" -Path "$gpoDir\Domain" -TargetName "$domain - Разрешить запись CD/DVD" -CreateIfNeeded | Out-Null
##### Пометка ДЛЯ ВАСЯНА - не забудь сначала добавить разрешаюшее правило для RDP в брандмауэре что бы не словить инфаркт жопы 
Import-GPO -BackupId "{7CF733B4-9615-4873-ADA5-048D52A443DE}" -Path "$gpoDir\Domain" -TargetName "$domain - Отключение соединения с Интернетом" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{39279DBB-E09B-41DB-BB5D-543D373D290D}" -Path "$gpoDir\Domain" -TargetName "$domain - Server" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{54B825EA-04CD-4D93-818A-8A61E56A6677}" -Path "$gpoDir\Domain" -TargetName "$domain - User" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{B39206B4-164D-468C-A75B-C0DEFE063C79}" -Path "$gpoDir\Domain" -TargetName "$domain - Computer" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{E6980432-EC0F-48C7-8687-F740714D30EC}" -Path "$gpoDir\Domain" -TargetName "$domain - Сетевые диски" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{B52C5A99-1449-4DDE-8765-D14295EC3FC6}" -Path "$gpoDir\Domain" -TargetName "WSUS - Настройка сервера обновлений" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{F88E4011-66FE-48EF-A6D9-ACAAB6F7B62B}" -Path "$gpoDir\Domain" -TargetName "WSUS - Настройка серверов" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{3FFDE1CB-5DBD-46E2-82C9-3EC2C998EDBB}" -Path "$gpoDir\Domain" -TargetName "WSUS - Настройка клиентских ПК" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{47F97955-EDBE-4D61-BAC1-A8EFBC2E921C}" -Path "$gpoDir\Domain" -TargetName "WSUS - Обновление Office 2021" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{A9E45958-9722-4E45-B14F-45D6B8F36E92}" -Path "$gpoDir\Domain" -TargetName "Audit - Настройки DC для Netwrix" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{7EE57ACB-2181-41FF-A140-93ADCF1FD60D}" -Path "$gpoDir\Domain" -TargetName "Audit - Настройки FS для Netwrix" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{DB7998E8-09A2-4856-8DA7-6AAD1A524E24}" -Path "$gpoDir\Domain" -TargetName "Audit - Сбор журналов печати" -CreateIfNeeded | Out-Null
Import-GPO -BackupId "{4C790A8F-920C-4404-960B-F788E38FA620}" -Path "$gpoDir\Domain" -TargetName "WinRM - Включить службу" -CreateIfNeeded | Out-Null
```

### Не используем, в новых редакциях винды LAPS встроен в систему и легаси лапс через msi больше не нужен
```powershell
# Создание пустых GPO (необходимо вручную добавить ПО для установки)
#(New-GPO -Name "LAPS - Установка x86").GpoStatus = "UserSettingsDisabled"
#(New-GPO -Name "LAPS - Установка x64").GpoStatus = "UserSettingsDisabled"
# Применение WMI фильтров к GPO
#Get-GPO -Name "LAPS - Установка x86" | Set-GPWmiFilterAssignment -Filter "Only x86 OS"
#Get-GPO -Name "LAPS - Установка x64" | Set-GPWmiFilterAssignment -Filter "Only x64 OS"
#Get-GPO -Name "MSFT SMB v1 client for pre-Win8.1/2012R2" | Set-GPWmiFilterAssignment -Filter "Windows 7-8 and Servers 2008-2012"
# Создание пустых GPO (Далее по тексту НЕ используем legacy)
(New-GPO -Name "LAPS - Конфигурация (Windows LAPS)").GpoStatus = "UserSettingsDisabled"
#### Подготавливаем схему AD для LAPS
```powershell
Import-Module LAPS
Update-LapsADSchema
#Если по какой-то непонятной причине ты забыл заполнить переменную
$DomainCN = (Get-ADDomain).DistinguishedName
Set-LapsADComputerSelfPermission -Identity "OU=Domain Computers,$DomainCN"
Set-LapsADComputerSelfPermission -Identity "OU=Domain Servers,$DomainCN"
## Разрешаем доменным админам смотреть пароли
Set-LapsADReadPasswordPermission -Identity "OU=Domain Computers,$DomainCN" -AllowedPrincipals "Администраторы домена"
Set-LapsADReadPasswordPermission -Identity "OU=Domain Servers,$DomainCN" -AllowedPrincipals "Администраторы домена"
# Создаём ключ для шифрования пароля
# Проверяем и запускаем службу KDS
Get-Service kdssvc | Set-Service -StartupType Auto
Start-Service kdssvc
Start-Sleep -Seconds 5
Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
# Выставляем политику: 1. Где хранятся пароли, 2. Шифрование пароля, 3. Сложность пароля, 4. Длинна пароля, 5. Аудит пароля, после использования LAPS сразу меняем пароль, 6. Настраиваем автоматическую ротацию паролей через $ дней 
Set-GPRegistryValue -Name "LAPS - Конфигурация (Windows LAPS)" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS" -ValueName "BackupDirectory" -Type DWord -Value 1
Set-GPRegistryValue -Name "LAPS - Конфигурация (Windows LAPS)" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS" -ValueName "PasswordEncryptionEnabled" -Type DWord -Value 1
Set-GPRegistryValue -Name "LAPS - Конфигурация (Windows LAPS)" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS" -ValueName "PasswordComplexity" -Type DWord -Value 4
Set-GPRegistryValue -Name "LAPS - Конфигурация (Windows LAPS)" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS" -ValueName "PasswordLength" -Type DWord -Value 16
# 5. Пометка после использования пароля LAPS он меняется, админа не выкидывет из сеанса, но следующий заход потребует снова смотреть пароль
Set-GPRegistryValue -Name "LAPS - Конфигурация (Windows LAPS)" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS" -ValueName "PostAuthenticationActions" -Type DWord -Value 1
Set-GPRegistryValue -Name "LAPS - Конфигурация (Windows LAPS)" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS" -ValueName "PasswordAgeDays" -Type DWord -Value 30
```

#### Привязываем созданные GPO к OU
```powershell
# DOMAIN
New-GPLink -Name "WSUS - Настройка сервера обновлений" -Target $domainCN | Set-GPLink -Order 1 | Out-Null
New-GPLink -Name "$domain - Отключение соединения с Интернетом" -Target $domainCN | Set-GPLink -Order 2 | Out-Null
New-GPLink -Name "MSFT Windows Server 2022 - Domain Security" -Target $domainCN | Set-GPLink -Order 3 | Out-Null
# DOMAIN CONTROLLERS
New-GPLink -Name "Audit - Настройки DC для Netwrix" -Target "OU=Domain Controllers,$domainCN" | Set-GPLink -Order 1 | Out-Null
#ДЛЯ ЛАБЫ не забудь прокинуть RDP ЗА РАНЕЕ!
New-GPLink -Name "MSFT Windows Server 2022 - Domain Controller" -Target "OU=Domain Controllers,$domainCN" | Set-GPLink -Order 2 | Out-Null
# DOMAIN SERVERS
New-GPLink -Name "$domain - Server" -Target "OU=Domain Servers,$domainCN" | Set-GPLink -Order 1 | Out-Null
New-GPLink -Name "Audit - Сбор журналов печати" -Target "OU=Domain Servers,$domainCN" | Set-GPLink -Order 2 | Out-Null
New-GPLink -Name "Audit - Настройки FS для Netwrix" -Target "OU=Domain Servers,$domainCN" | Set-GPLink -Order 3 | Out-Null # Указать только для файловых серверов!
New-GPLink -Name "WSUS - Настройка серверов" -Target "OU=Domain Servers,$domainCN" | Set-GPLink -Order 4 | Out-Null
New-GPLink -Name "LAPS - Конфигурация (Windows LAPS)" -Target "OU=Domain Servers,$domainCN" | Set-GPLink -Order 5 | Out-Null
#New-GPLink -Name "LAPS - Установка x64" -Target "OU=Domain Servers,$domainCN" | Set-GPLink -Order 5 | Out-Null
New-GPLink -Name "MSFT Windows Server 2022 - Member Server" -Target "OU=Domain Servers,$domainCN" | Set-GPLink -Order 6 | Out-Null
# DOMAIN COMPUTERS
New-GPLink -Name "$domain - Computer" -Target "OU=Domain Computers,$domainCN" | Set-GPLink -Order 1 | Out-Null
New-GPLink -Name "WinRM - Включить службу" -Target "OU=Domain Computers,$domainCN" | Set-GPLink -Order 2 | Out-Null
New-GPLink -Name "Audit - Сбор журналов печати" -Target "OU=Domain Computers,$domainCN" | Set-GPLink -Order 3 | Out-Null
New-GPLink -Name "WSUS - Обновление Office 2021" -Target "OU=Domain Computers,$domainCN" | Set-GPLink -Order 4 | Out-Null
New-GPLink -Name "WSUS - Настройка клиентских ПК" -Target "OU=Domain Computers,$domainCN" | Set-GPLink -Order 5 | Out-Null
New-GPLink -Name "LAPS - Конфигурация (Windows LAPS)" -Target "OU=Domain Computers,$DomainCN" | Set-GPLink -Order 6 | Out-Null
#New-GPLink -Name "LAPS - Установка x86" -Target "OU=Domain Computers,$domainCN" | Set-GPLink -Order 6 | Out-Null
#New-GPLink -Name "LAPS - Установка x64" -Target "OU=Domain Computers,$domainCN" | Set-GPLink -Order 7 | Out-Null
New-GPLink -Name "MSFT SMB v1 client for pre-Win8.1/2012R2" -Target "OU=Domain Computers,$domainCN" | Set-GPLink -Order 7 | Out-Null
New-GPLink -Name "MSFT Windows 10 21H2 - Computer" -Target "OU=Domain Computers,$domainCN" | Set-GPLink -Order 8 | Out-Null
# DOMAIN USERS
New-GPLink -Name "$domain - Разрешить запись CD/DVD" -Target "OU=Domain Users,$domainCN" | Set-GPLink -Order 1 | Out-Null # Указать только отдельных пользователей!
New-GPLink -Name "$domain - Сетевые диски" -Target "OU=Domain Users,$domainCN" | Set-GPLink -Order 2 | Out-Null
New-GPLink -Name "$domain - User" -Target "OU=Domain Users,$domainCN" | Set-GPLink -Order 3 | Out-Null
New-GPLink -Name "MSFT Windows 10 21H2 - User" -Target "OU=Domain Users,$domainCN" | Set-GPLink -Order 4 | Out-Null
```

## Создание учетных записей

#### Импорт фейковых пользователей из файла `accounts.csv`

```powershell
Import-Csv -Path "C:\GPO\accounts.csv" | Select-Object `
  @{Name="Name";Expression={$_.Username}},
  @{Name="UserPrincipalName"; Expression={$_.Username +"@domain.lab"}},
  @{Name="SamAccountName"; Expression={$_.Username}},
  @{Name="GivenName";Expression={$_.GivenName}},
  @{Name="Surname";Expression={$_.Surname}},
  @{Name="Description"; Expression={$_.Surname + " " + $_.GivenName}},
  @{Name="DisplayName"; Expression={$_.Surname + " " + $_.GivenName}},
  @{Name="AccountPassword"; Expression={(Convertto-SecureString -Force -AsPlainText "Password1234@!")}},
  @{Name="Path"; Expression={"OU=Domain Users,DC=domain,DC=lab"}},
  @{Name="Enabled"; Expression={$true}},
  @{Name="ChangePasswordAtLogon"; Expression={$false}},
  @{Name="PasswordNeverExpires"; Expression={$true}} `
| ForEach-Object -Process { $_ | New-ADUser }
```

#### Создание отдельного пользователя через PowerShell

```powershell
New-Object PSObject -Property @{
  Name                  = "Ivanov"
  UserPrincipalName     = "Ivanov@domain.lab"
  SamAccountName        = "Ivanov"
  GivenName             = "Иван"
  Surname               = "Иванов"
  Description           = "Иванов И.И."
  DisplayName           = "Иванов И.И."
  AccountPassword       = (ConvertTo-SecureString -Force -AsPlainText "Password1234@!")
  Path                  = "OU=Domain Users,DC=domain,DC=lab"
  Enabled               = $true
  ChangePasswordAtLogon = $false
  PasswordNeverExpires  = $true
} | New-ADUser
```

#### Создание учетки администратора домена `root`

```powershell
$password = "Password1234@!" | ConvertTo-SecureString -AsPlainText -Force
New-ADUser -Name root -UserPrincipalName "root@domain.lab" -AccountPassword $password -ChangePasswordAtLogon $false -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember "Администраторы домена" root
```

#### Создание групп для администраторов безопасности

```powershell
New-ADGroup -Name "Администраторы домена безопасности" -SamAccountName "SecDomainAdmin" -Path "OU=Domain Users,DC=domain,DC=lab" -GroupCategory "Security" -Description "Администраторы леса безопасности" -GroupScope "Global" -PassThru

New-ADGroup -Name "Администраторы леса безопасности" -SamAccountName "SecForestAdmins" -Path "OU=Domain Users,DC=domain,DC=lab" "Security" -Description "Администраторы леса безопасности" -GroupScope "Global" -PassThru
```
#### Создание пользователя rootts для администраторов безопасности

```powershell
$password = "Password1234@!" | ConvertTo-SecureString -AsPlainText -Force
New-ADUser -Name "rootts" -SamAccountName "rootts" -UserPrincipalName "rootts@domain.lab" -Path "OU=Domain Users,DC=domain,DC=lab" -AccountPassword $password -ChangePasswordAtLogon $false -Enabled $true -PasswordNeverExpires $true -PassThru
```
#### Добавление rootts в группы безопасности

```powershell
Add-ADGroupMember -Identity "SecForestAdmins" -Members "rootts" -PassThru
Add-ADGroupMember -Identity "SecDomainAdmins" -Members "rootts" -PassThru
```

###### После развёртывания сервера безопасности добавить туда пользователя rootts 
```powershell
    Invoke-Command -ComputerName "TrustCover" -ScriptBlock {
    $AdminGroup = Get-LocalGroup | Where-Object { $_.SID -like "S-1-5-32-544" }
      Add-LocalGroupMember -Group $AdminGroup -Member "domain\rootts"
}
```


#### Создание групп отделов и добавление туда пользователей

```powershell
New-ADGroup -Name "1 Отдел" -SamAccountName "1 Отдел" -Path "OU=Domain Users,DC=domain,DC=lab" -GroupCategory "Security" -Description "1 Отдел" -GroupScope "Global" -PassThru
New-ADGroup -Name "2 Отдел" -SamAccountName "2 Отдел" -Path "OU=Domain Users,DC=domain,DC=lab" -GroupCategory "Security" -Description "2 Отдел" -GroupScope "Global" -PassThru
New-ADGroup -Name "3 Отдел" -SamAccountName "3 Отдел" -Path "OU=Domain Users,DC=domain,DC=lab" -GroupCategory "Security" -Description "3 Отдел" -GroupScope "Global" -PassThru
$users = Get-ADUser -Filter * -SearchBase "OU=Domain Users,DC=domain,DC=lab"
$users | Select-Object -First 15 | ForEach-Object { Add-ADGroupMember "1 Отдел" -Members $_ }
$users | Select-Object -First 15 -Skip 15 | ForEach-Object { Add-ADGroupMember "2 Отдел" -Members $_ }
$users | Select-Object -Skip 30 | ForEach-Object { Add-ADGroupMember "3 Отдел" -Members $_ }
```
