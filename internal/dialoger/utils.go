package dialoger

import "fmt"

var intro_s1 = "Привет! Это консольное приложения для отслеживания arp-пакетов на основе pcap"
var intro_s2 = "Список команд:"
var intro_s3 = "\t1) Захват arp-пакетов и их вывод в консоль. Использование: введите в косноль слово \"capture\" + Enter"
var intro_s4 = "\t2) Выяснить мак-адрес роутера с помощью arp-запроса. Использование: введите в консоль слово \"router_mac\" + Enter"
var intro_s5 = "\t3) Получить статистику за какое-то время. Использование: введите в консоль \"statistics --time=<время в секундах>\" + Enter"
var intro_s6 = "\t4) Завершить работу программы. Использование: введите в консоль слово \"exit\" + Enter"
var intro_s7 = "\t5) Увидеть список команд. Использование: введите в консоль слово \"help\" + Enter"
var introduction = fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n", intro_s1, intro_s2, intro_s3, intro_s4, intro_s5, intro_s6, intro_s7)

var STATISTICS_PREFFIX = "statistics --time="
