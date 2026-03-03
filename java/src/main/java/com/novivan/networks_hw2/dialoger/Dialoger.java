package com.novivan.networks_hw2.dialoger;

import com.novivan.networks_hw2.pcap.PcapProcesser;
import java.util.Scanner;

public class Dialoger {
    private final PcapProcesser processer;

    public Dialoger() {
        this.processer = new PcapProcesser();
    }

    public void run() throws Exception {
        Scanner reader = new Scanner(System.in);
        boolean wannaBreak = false;
        
        for (int iteration = 0; !wannaBreak; iteration++) {
            if (iteration == 0) {
                System.out.println(DialogerUtils.INTRODUCTION);
            }
            
            String inp = reader.nextLine().trim();
            
            switch (inp) {
                case "capture":
                    System.out.println("capturing ARPs...");
                    try {
                        processer.handleAllPackets();
                    } catch (Exception e) {
                        System.out.printf("Error capturing packets: %s%n", e.getMessage());
                    }
                    break;
                    
                case "router_mac":
                    System.out.println("Определение MAC-адреса роутера...");
                    System.out.println();
                    System.out.println("Для нахождения IP-адреса роутера можно использовать команду:");
                    System.out.println("   netstat -rn | grep default"); // из-за мака...
                    System.out.println();
                    System.out.print("Введите IP-адрес роутера: ");
                    String routerIp = reader.nextLine().trim();
                    
                    if (routerIp.isEmpty()) {
                        System.out.println("IP-адрес не введён");
                        break;
                    }
                    
                    if (!isValidIpAddress(routerIp)) {
                        System.out.println("Некорректный формат IP-адреса");
                        break;
                    }
                    
                    System.out.println();
                    try {
                        String mac = processer.getRouterMac(routerIp);
                        if (mac != null) {
                            System.out.println();
                            System.out.println();
                            System.out.println("РЕЗУЛЬТАТ: MAC-адрес роутера (" + routerIp + "): " + mac);
                            System.out.println("");
                        }
                    } catch (Exception e) {
                        System.out.printf("Ошибка при получении MAC-адреса: %s%n", e.getMessage());
                        e.printStackTrace();
                    }
                    break;
                    
                case "exit":
                    System.out.println("exiting...");
                    wannaBreak = true;
                    break;
                    
                case "help":
                    System.out.println(DialogerUtils.INTRODUCTION);
                    break;
                    
                default:
                    if (inp.startsWith(DialogerUtils.STATISTICS_PREFIX)) {
                        String usefulInfo = inp.substring(DialogerUtils.STATISTICS_PREFIX.length()).trim();
                        try {
                            int seconds = Integer.parseInt(usefulInfo.split(" ")[0]);
                            
                            System.out.println("Для подсчёта трафика с роутером нужен его IP-адрес.");
                            System.out.println("Команда для определения IP роутера: netstat -rn | grep default");
                            System.out.print("Введите IP-адрес роутера (или Enter для пропуска): ");
                            String routerIpForStats = reader.nextLine().trim();
                            
                            if (!routerIpForStats.isEmpty() && !isValidIpAddress(routerIpForStats)) {
                                System.out.println("Некорректный формат IP-адреса, трафик с роутером не будет подсчитан");
                                routerIpForStats = null;
                            }

                            System.out.printf("Собираю статистику на протяжении %d секунд...%n", seconds);

                            try {
                                PcapProcesser.NetworkStatistics stats = processer.collectStatistics(seconds, routerIpForStats);
                                if (stats != null) {
                                    System.out.println(stats.toString());
                                }
                            } catch (Exception e) {
                                System.out.printf("Ошибка при сборе статистики: %s%n", e.getMessage());
                                e.printStackTrace();
                            }
                            
                        } catch (NumberFormatException e) {
                            System.out.println("Неправильно введена команда");
                            System.out.printf("\tОшибка: %s%n", e.getMessage());
                            System.out.println("\tДля просмотра списка команд введите \"help\" + Enter");
                        }
                    } else {
                        System.out.println("Команда введена неправильно. Для просмотра доступных команд введите \"help\" + Enter");
                    }
                    break;
            }
        }
        reader.close();
    }
    
    private boolean isValidIpAddress(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        try {
            for (String part : parts) {
                int value = Integer.parseInt(part);
                if (value < 0 || value > 255) {
                    return false;
                }
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
