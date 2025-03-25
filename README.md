## Информация / Information

Скрипт для циклического автоматизированно сбора хешей с большого количества серверов синхронизации времени контроллеров домена Microsoft Windows. Скрипт доработан на основе скрипта `https://github.com/SecuraBV/Timeroast`

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
