package com.novivan.networks_hw2.pcap;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.util.NifSelector;


public class PcapProcesser {
    private static final String DEVICE = "en0";
    private static final String FILTER = "arp";
    private static final int SNAPLEN = 1600;
    private static final int TIMEOUT = 10; // миллисекунды
    private static final int packetsToCatch = 15;

    public PcapProcesser() {
    }

    public String handleAllPackets() throws Exception {
        PcapNetworkInterface nif = new NifSelector().selectNetworkInterface();
        if (nif == null) {
            System.err.println("Сетевой интерфейс не найден");
            return null;
        }
        try (PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT)) {
            handle.setFilter(FILTER, BpfProgram.BpfCompileMode.OPTIMIZE);

            System.out.println("Захват ARP-пакетов...");

            handle.loop(packetsToCatch, (PacketListener) (packet) -> {
                byte[] raw = packet.getRawData();

                if (raw.length < 42) {
                    System.out.println("Пакет слишком короткий: " + raw.length);
                    return;
                }

                System.out.println("\n========================================");
                System.out.println("ARP пакет получен! Длина: " + raw.length);

                // === ETHERNET HEADER (первые 14 байт) ===
                String dstMac = formatMac(raw, 0);
                String srcMac = formatMac(raw, 5);

                int etherType = ((raw[12] & 0xFF) << 8) | (raw[13] & 0xFF);

                System.out.println("\n--- Ethernet Header ---");
                System.out.println("Destination MAC: " + dstMac);
                System.out.println("Source MAC: " + srcMac);
                System.out.println("EtherType: 0x" + String.format("%04x", etherType) + 
                    (etherType == 0x0806 ? " (ARP)" : ""));
                
                 // === ARP HEADER (начинается с байта 14) ===
                int hardwareType = ((raw[14] & 0xFF) << 8) | (raw[15] & 0xFF);
                int protocolType = ((raw[16] & 0xFF) << 8) | (raw[17] & 0xFF);
                int hardwareSize = raw[18] & 0xFF;
                int protocolSize = raw[19] & 0xFF;
                int operation = ((raw[20] & 0xFF) << 8) | (raw[21] & 0xFF);
                
                String senderMac = formatMac(raw, 22);
                String senderIp = formatIp(raw, 28);
                String targetMac = formatMac(raw, 32);
                String targetIp = formatIp(raw, 38);
            
                System.out.println("\n--- ARP Header ---");
                System.out.println("Hardware Type: " + hardwareType + (hardwareType == 1 ? " (Ethernet)" : ""));
                System.out.println("Protocol Type: 0x" + String.format("%04x", protocolType) + 
                    (protocolType == 0x0800 ? " (IPv4)" : ""));
                System.out.println("Hardware Size: " + hardwareSize);
                System.out.println("Protocol Size: " + protocolSize);
                System.out.println("Operation: " + operation + " (" + getOperationName(operation) + ")");
                
                System.out.println("\n--- ARP Data ---");
                System.out.println("Sender MAC: " + senderMac);
                System.out.println("Sender IP:  " + senderIp);
                System.out.println("Target MAC: " + targetMac);
                System.out.println("Target IP:  " + targetIp);
                

                // Красивый вывод сути запроса
                System.out.println("\n>>> " + formatArpMessage(operation, senderMac, senderIp, targetMac, targetIp));
                
                System.out.println("========================================");
            });
        } catch (Exception e) {
           e.printStackTrace();
        }
        return null;
    }

    private static String formatMac(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }
    
    private static String formatIp(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            if (i > 0) sb.append(".");
            sb.append(data[offset + i] & 0xFF);
        }
        return sb.toString();
    }
    
    private static String getOperationName(int operation) {
        switch (operation) {
            case 1: return "ARP REQUEST";
            case 2: return "ARP REPLY";
            case 3: return "RARP REQUEST";
            case 4: return "RARP REPLY";
            default: return "UNKNOWN";
        }
    }
    
    private static String formatArpMessage(int operation, String senderMac, String senderIp, 
                                           String targetMac, String targetIp) {
        if (operation == 1) {
            return String.format("Кто имеет IP %s? Сообщите %s (%s)", targetIp, senderIp, senderMac);
        } else if (operation == 2) {
            return String.format("%s имеет MAC %s (сообщение для %s)", senderIp, senderMac, targetIp);
        }
        return "Неизвестная операция";
    }
}
