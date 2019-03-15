# ФПИ - распознавание сетевых атак

Для корректной работы программы понадобятся следующее ПО: python, pip, tshark.

Установка необходимых программ:

  Установить python:

  ```
  sudo apt install python3
  ```

  Установить pip:

  ```
  sudo apt install python3-pip
  ```

  Установить tshark:

  ```
  sudo apt-get install wireshark tshark
  ```

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
