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
                    System.out.println("finding router mac address...");
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
                        String usefulInfo = inp.substring(DialogerUtils.STATISTICS_PREFIX.length());
                        try {
                            int seconds = Integer.parseInt(usefulInfo.split(" ")[0]);
                            System.out.printf("Собираю статистику на протяжении %d секунд...%n", seconds);
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
}
