package com.novivan.networks_hw2.pcap;

import java.util.Arrays;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;


public class PcapProcesser {
    private static final int BYTE_SIZE = 8;
    private static final String DEVICE = "en0";
    private static final String FILTER = "arp";
    private static final int SNAPLEN = 500;
    private static final int TIMEOUT = 10; // миллисекунды
    private static final int packetsToCatch = 5;

    //размеры кусков arp-пакета (в байтах)
    private static final int HTYPE_SIZE = 2;
    private static final int PTYPE_SIZE = 2;
    private static final int HLEN_SIZE = 1;
    private static final int PLEN_SIZE = 1;
    private static final int OPERATION_SIZE = 2;

    private static Integer HARDWARE_ADDRESS_SIZE = null;
    private static Integer PROTOCOL_ADDRESS_SIZE = null;


    public PcapProcesser() {
    }

    public String handleAllPackets() throws Exception {
        PcapNetworkInterface nif = Pcaps.getDevByName(DEVICE); // писал на маке, сделал под него
        if (nif == null) {
            System.err.println("Сетевой интерфейс не найден");
            return null;
        }
        try (PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT)) {
            handle.setFilter(FILTER, BpfProgram.BpfCompileMode.OPTIMIZE);

            System.out.println("Захват ARP-пакетов...");

            handle.loop(packetsToCatch, (PacketListener) (packet) -> {
                byte[] raw = packet.getRawData();

                System.out.println("ARP-пакет получен! Длина - " + raw.length + " байт.");
                

                byte[] destination_mac_bytes = Arrays.copyOfRange(raw, 0, 6);
                long destination_mac_number = 0;
                for (int i = 0; i < 6; i++) {
                    destination_mac_number += (long)(destination_mac_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\tТа часть, которую мы почему-то тоже получили (кажется, должна быть вне ARP-пакета - прям перед ним (в ethernet-пакете - обертке arp)");
                System.out.println("\t\tDestination MAC(6 bytes) - " + formatMac(destination_mac_number));

                byte[] source_mac_bytes = Arrays.copyOfRange(raw, 6, 12);
                long source_mac_number = 0;
                for (int i = 0; i < 6; i++) {
                    source_mac_number += (long)(source_mac_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tSource MAC(6 bytes) - " + formatMac(source_mac_number));
                

                byte[] ether_type_bytes = Arrays.copyOfRange(raw, 12, 14);
                int ether_type = 0;
                for (int i = 0; i < 2; i++) {
                    ether_type += (ether_type_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tEther type(2 bytes) - " + ether_type);


                System.out.println("\tТело пакета:\n");

                int current_shift = 14;
                
                // hardware type
                byte[] hardware_type_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + HTYPE_SIZE);
                int hardware_type = 0;
                for (int i = 0; i < HTYPE_SIZE; i++) {
                    hardware_type += (hardware_type_bytes[i] & 0xFF) << (BYTE_SIZE * (HTYPE_SIZE - 1 - i));
                    //hardware_type += (hardware_type_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tHardware type - " + hardware_type + " (" + HardwareType.fromInt(hardware_type).toString() +")");
                current_shift += HTYPE_SIZE;

                // protocol type
                byte[] protocol_type_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + PTYPE_SIZE);
                int protocol_type = 0;
                for (int i = 0; i < PTYPE_SIZE; i++) {
                    //protocol_type += (protocol_type_bytes[i] & 0xFF) << (BYTE_SIZE * (PTYPE_SIZE - 1 - i));
                    protocol_type += (protocol_type_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tProtocol type - " + protocol_type);
                current_shift += PTYPE_SIZE;

                // hardware address len
                byte[] hardware_address_len_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + HLEN_SIZE);
                int hardware_address_len = 0;
                for (int i = 0; i < HLEN_SIZE; i++) {
                    //hardware_address_len += (hardware_address_len_bytes[i] & 0xFF) << (BYTE_SIZE * (HLEN_SIZE - 1 - i));
                    hardware_address_len += (hardware_address_len_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tHardware address len - " + hardware_address_len);
                current_shift += HLEN_SIZE;

                byte[] protocol_type_len_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + PLEN_SIZE);
                int protocol_type_len = 0;
                for (int i = 0; i < PLEN_SIZE; i++) {
                    //protocol_type_len += (protocol_type_len_bytes[i] & 0xFF) << (BYTE_SIZE * (PLEN_SIZE - 1 - i));
                    protocol_type_len += (protocol_type_len_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tProtocol type len - " + protocol_type_len);
                current_shift += PLEN_SIZE;

                // Operation type
                byte[] operation_type_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + OPERATION_SIZE);
                int operation_type = 0;
                for (int i = 0; i < OPERATION_SIZE; i++) {
                    //operation_type += (operation_type_bytes[i] & 0xFF) << (BYTE_SIZE * (OPERATION_SIZE - 1 - i));
                    operation_type += (operation_type_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tOperation type - " + operation_type);
                current_shift += OPERATION_SIZE;

                

                HARDWARE_ADDRESS_SIZE = Integer.valueOf(hardware_address_len);
                PROTOCOL_ADDRESS_SIZE = Integer.valueOf(protocol_type_len);

                // sender hardware address
                byte[] sender_hardware_adress_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + HARDWARE_ADDRESS_SIZE);
                Long sender_hardware_adress = Long.valueOf(0);
                for (int i = 0; i < HARDWARE_ADDRESS_SIZE; i++) {
                    sender_hardware_adress += (sender_hardware_adress_bytes[i] & 0xFF) << (BYTE_SIZE * (HARDWARE_ADDRESS_SIZE - 1 - i));
                    //sender_hardware_adress += (sender_hardware_adress_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tSender hardware address - " + formatMac(sender_hardware_adress, HARDWARE_ADDRESS_SIZE));
                current_shift += HARDWARE_ADDRESS_SIZE;

                // sender protocol address
                byte[] sender_protocol_address_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + PROTOCOL_ADDRESS_SIZE);
                Long sender_protocol_address = Long.valueOf(0);
                for (int i = 0; i < PROTOCOL_ADDRESS_SIZE; i++) {
                    //sender_protocol_address += (sender_protocol_address_bytes[i] & 0xFF) << (BYTE_SIZE * (PROTOCOL_ADDRESS_SIZE - 1 - i));
                    sender_protocol_address += (sender_protocol_address_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tSender protocol address - " + formatIp(sender_protocol_address));
                current_shift += PROTOCOL_ADDRESS_SIZE;

                // target hardware address
                byte[] target_hardware_address_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + HARDWARE_ADDRESS_SIZE);
                Long target_hardware_address = Long.valueOf(0);
                for (int i = 0; i < HARDWARE_ADDRESS_SIZE; i++) {
                    target_hardware_address += (target_hardware_address_bytes[i] & 0xFF) << (BYTE_SIZE * (HARDWARE_ADDRESS_SIZE - 1 - i));
                    //target_hardware_address += (target_hardware_address_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tTarget hardware address - " + formatMac(target_hardware_address, HARDWARE_ADDRESS_SIZE));
                current_shift += HARDWARE_ADDRESS_SIZE;

                // target protocol address
                byte[] target_protocol_address_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + PROTOCOL_ADDRESS_SIZE);
                Long target_protocol_address = Long.valueOf(0);
                for (int i = 0; i < PROTOCOL_ADDRESS_SIZE; i++) {
                    //target_protocol_address += (target_protocol_address_bytes[i] & 0xFF) << (BYTE_SIZE * (PROTOCOL_ADDRESS_SIZE - 1 - i));
                    target_protocol_address += (target_protocol_address_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tTarget protocol address - " + formatIp(target_protocol_address));
                current_shift += PROTOCOL_ADDRESS_SIZE;
                System.out.println("Конец пакета");
                System.out.println("========================================");




                //System.out.printf("ARP пакет получен! Его длина - %d", raw.length);

                /*if (raw.length < 42) {
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
                */
            });
            System.out.println("Установленное кол-во пакетов(" + packetsToCatch + ") получено! Операция завершена");
        } catch (Exception e) {
           e.printStackTrace();
        }
        return null;
    }
    private static String formatMac(long data) {
        return formatMac(data, 6);
    }
    private static String formatMac(long data, long sz) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < sz; i++) {
            sb.append(String.format("%02x", ((data & ((long)0xFF << (i * 8))) >> (i * 8))));
            if (i < sz - 1) sb.append(":");
        }
        return sb.toString();
    }

    private static String formatIp(long data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            sb.append(String.format("%d", ((data & ((long)0xFF << (i * 8))) >> (i * 8))));
            if (i < 3) sb.append(".");
        }
        return sb.toString();
    }

    private enum HardwareType {
        Ethernet (1),
        IEEE (6),
        FrameRelay (15),
        SerialLine (20);

        private final int hardwareType;

        HardwareType(int hardwareType) {
            this.hardwareType = hardwareType;
        }

        public int getHardwareType() {
            return hardwareType;
        }

        public static HardwareType fromInt(int value) throws IllegalArgumentException {
            for (HardwareType type : HardwareType.values()) {
                if (type.getHardwareType() == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Unknown hardware type: " + value);
        }

        @Override
        public String toString() {
            return switch (hardwareType) {
                case 1 -> "Ethernet";
                case 6 -> "IEEE 802";
                case 15 -> "FrameRelay";
                case 20 -> "SerialLine";
                default -> "Unknown";
            };
        }
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
