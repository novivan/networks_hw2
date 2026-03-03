package com.novivan.networks_hw2.dialoger;

public class DialogerUtils {
    private static final String INTRO_S1 = "Привет! Это консольное приложение для отслеживания arp-пакетов на основе pcap";
    private static final String INTRO_S2 = "Список команд:";
    private static final String INTRO_S3 = "\t1) Захват arp-пакетов и их вывод в консоль. Использование: введите в консоль слово \"capture\" + Enter";
    private static final String INTRO_S4 = "\t2) Выяснить мак-адрес роутера с помощью arp-запроса. Использование: введите в консоль слово \"router_mac\" + Enter (вообще туда можно вписать любой ip из локальной сети - mac найдется, для этого и нужны arp-запросы)";
    private static final String INTRO_S5 = "\t3) Получить статистику за какое-то время. Использование: введите в консоль \"statistics --time=<время в секундах>\" + Enter";
    private static final String INTRO_S6 = "\t4) Завершить работу программы. Использование: введите в консоль слово \"exit\" + Enter";
    private static final String INTRO_S7 = "\t5) Увидеть список команд. Использование: введите в консоль слово \"help\" + Enter";
    
    public static final String INTRODUCTION = String.join("\n", 
        INTRO_S1, INTRO_S2, INTRO_S3, INTRO_S4, INTRO_S5, INTRO_S6, INTRO_S7);
    
    public static final String STATISTICS_PREFIX = "statistics --time=";
}
