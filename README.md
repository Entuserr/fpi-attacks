# ФПИ - распознавание сетевых атак

Установку необходимых модулей удобнее всего выполнять в виртуальном окружении:

Установить virtualenv:

```
python3 -m pip install --user virtualenv
```
Создать виртуальное окружение:
```
python3 -m virtualenv env
```
Активировать виртуальное окружение: 
```
source env/bin/activate
```
Установить необходимые модули: 
```
pip install -r requirements.txt
```
Запускать программу так как :

```
python fpi-attacks/analyze.py [путь к файлу .pcap либо папке с .pcap] [имя выходного файла]
```

Значения по умолчанию - ../data/Attacks_train/ и output.csv соответственно. 
