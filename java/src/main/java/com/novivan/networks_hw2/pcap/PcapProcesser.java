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
    private static final int packetsToCatch = 20;

    //размеры кусков arp-пакета (в байтах)
    private static final int HTYPE_SIZE = 2;
    private static final int PTYPE_SIZE = 2;
    private static final int HLEN_SIZE = 1;
    private static final int PLEN_SIZE = 1;
    private static final int OPERATION_SIZE = 2;


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

            System.out.println("========================================");

            handle.loop(packetsToCatch, (PacketListener) (packet) -> {
                byte[] raw = packet.getRawData();

                System.out.println("Ethernet-frame с ARP-пакетом получен! Длина фрейма - " + raw.length + " байт.");

                byte[] destination_mac_bytes = Arrays.copyOfRange(raw, 0, 6);
                long destination_mac_number = 0;
                for (int i = 0; i < 6; i++) {
                    destination_mac_number += (long)(destination_mac_bytes[i] & 0xFF) << (BYTE_SIZE * (5 - i));
                }
                System.out.println("\tВсе, кроме ARP:");
                System.out.println("\t\tDestination MAC(6 bytes) - " + formatMac(destination_mac_number));

                byte[] source_mac_bytes = Arrays.copyOfRange(raw, 6, 12);
                long source_mac_number = 0;
                for (int i = 0; i < 6; i++) {
                    source_mac_number += (long)(source_mac_bytes[i] & 0xFF) << (BYTE_SIZE * (5 - i));
                }
                System.out.println("\t\tSource MAC(6 bytes) - " + formatMac(source_mac_number));
                

                byte[] ether_type_bytes = Arrays.copyOfRange(raw, 12, 14);
                int ether_type = 0;
                for (int i = 0; i < 2; i++) {
                    ether_type += (ether_type_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tEther type(2 bytes) - " + ether_type);
                System.out.println("\tСам ARP-пакет:");
                int current_shift = 14;
                
                byte[] hardware_type_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + HTYPE_SIZE);
                int hardware_type = 0;
                for (int i = 0; i < HTYPE_SIZE; i++) {
                    hardware_type += (hardware_type_bytes[i] & 0xFF) << (BYTE_SIZE * (HTYPE_SIZE - 1 - i));
                }
                System.out.println("\t\tHardware type - " + hardware_type + " (" + HardwareType.fromInt(hardware_type).toString() +")");
                current_shift += HTYPE_SIZE;

                byte[] protocol_type_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + PTYPE_SIZE);
                int protocol_type = 0;
                for (int i = 0; i < PTYPE_SIZE; i++) {
                    protocol_type += (protocol_type_bytes[i] & 0xFF) << (BYTE_SIZE * (PTYPE_SIZE - 1 - i));
                }
                System.out.println("\t\tProtocol type - " + protocol_type + " (" + ProtocolType.fromInt(protocol_type).toString() +")");
                current_shift += PTYPE_SIZE;

                byte[] hardware_address_len_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + HLEN_SIZE);
                int hardware_address_len = 0;
                for (int i = 0; i < HLEN_SIZE; i++) {
                    hardware_address_len += (hardware_address_len_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tHardware address len - " + hardware_address_len);
                current_shift += HLEN_SIZE;

                byte[] protocol_type_len_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + PLEN_SIZE);
                int protocol_address_len = 0;
                for (int i = 0; i < PLEN_SIZE; i++) {
                    protocol_address_len += (protocol_type_len_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tProtocol address len - " + protocol_address_len);
                current_shift += PLEN_SIZE;

                byte[] operation_type_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + OPERATION_SIZE);
                int operation_type = 0;
                for (int i = 0; i < OPERATION_SIZE; i++) {
                    operation_type += (operation_type_bytes[i] & 0xFF) << (BYTE_SIZE * (OPERATION_SIZE - 1 - i));
                }
                System.out.println("\t\tOperation type - " + operation_type + " (" + OperationType.fromInt(operation_type).toString() + ")");
                current_shift += OPERATION_SIZE;

                Integer SumSizesOfConstSizeFields = current_shift;

                Integer HARDWARE_ADDRESS_SIZE = Integer.valueOf(hardware_address_len);
                Integer PROTOCOL_ADDRESS_SIZE = Integer.valueOf(protocol_address_len);

                byte[] sender_hardware_adress_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + HARDWARE_ADDRESS_SIZE);
                Long sender_hardware_adress = Long.valueOf(0);
                for (int i = 0; i < HARDWARE_ADDRESS_SIZE; i++) {
                    sender_hardware_adress += ((long)sender_hardware_adress_bytes[i] & 0xFF) << (BYTE_SIZE * (HARDWARE_ADDRESS_SIZE - 1 - i));
                }
                System.out.println("\t\tSender hardware address - " + formatMac(sender_hardware_adress, HARDWARE_ADDRESS_SIZE));
                System.out.printf("\t\t");
                for (int i = 0; i < HARDWARE_ADDRESS_SIZE; i++) {
                    System.out.printf("%02x ", sender_hardware_adress_bytes[i]);
                }
                System.out.printf("\n");
                current_shift += HARDWARE_ADDRESS_SIZE;
                
                byte[] sender_protocol_address_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + PROTOCOL_ADDRESS_SIZE);
                Long sender_protocol_address = Long.valueOf(0);
                for (int i = 0; i < PROTOCOL_ADDRESS_SIZE; i++) {
                    sender_protocol_address += (sender_protocol_address_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tSender protocol address - " + formatIp(sender_protocol_address));
                current_shift += PROTOCOL_ADDRESS_SIZE;

                byte[] target_hardware_address_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + HARDWARE_ADDRESS_SIZE);
                Long target_hardware_address = Long.valueOf(0);
                for (int i = 0; i < HARDWARE_ADDRESS_SIZE; i++) {
                    target_hardware_address += ((long)target_hardware_address_bytes[i] & 0xFF) << (BYTE_SIZE * (HARDWARE_ADDRESS_SIZE - 1 - i));
                }
                System.out.println("\t\tTarget hardware address - " + formatMac(target_hardware_address, HARDWARE_ADDRESS_SIZE));
                System.out.printf("\t\t");
                for (int i = 0; i < HARDWARE_ADDRESS_SIZE; i++) {
                    System.out.printf("%02x ", target_hardware_address_bytes[i]);
                }
                System.out.printf("\n");
                current_shift += HARDWARE_ADDRESS_SIZE;

                byte[] target_protocol_address_bytes = Arrays.copyOfRange(raw, current_shift, current_shift + PROTOCOL_ADDRESS_SIZE);
                Long target_protocol_address = Long.valueOf(0);
                for (int i = 0; i < PROTOCOL_ADDRESS_SIZE; i++) {
                    target_protocol_address += (target_protocol_address_bytes[i] & 0xFF) << (BYTE_SIZE * i);
                }
                System.out.println("\t\tTarget protocol address - " + formatIp(target_protocol_address));
                current_shift += PROTOCOL_ADDRESS_SIZE;

                System.out.println("Оставшиеся байты:");
                
                for (int i = current_shift; i < raw.length; i++) {
                    if ((i - current_shift) % 8 == 0) {
                        System.out.print("\n\t\t");
                    }
                    System.out.printf("%02x ", raw[i]);
                }

                System.out.println("\nКонец пакета");
                System.out.println("========================================");
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
        for (int i = (int)sz - 1; i >= 0; --i) {
            sb.append(String.format("%02x", ((data & ((long)0xFF << (i * 8))) >> (i * 8))));
            if (i > 0) sb.append(":");
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

    private enum ProtocolType {
        IPv4 (0x0800);

        private final int protocolType;

        ProtocolType(int protocolType) {
            this.protocolType = protocolType;
        }

        public int getProtocolType() {
            return protocolType;
        }

        public static ProtocolType fromInt(int value) throws IllegalArgumentException {
            for (ProtocolType type : ProtocolType.values()) {
                if (type.getProtocolType() == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Unknown protocol type: " + value);
        }

        @Override
        public String toString() {
            return switch (protocolType) {
                case 0x0800 -> "IPv4";
                default -> "Unknown";
            };
        }
    }


    private enum OperationType {
        QUERY (0x0001),
        RESPONSE (0x0002);

        private final int operationType;

        OperationType(int operationType) {
            this.operationType = operationType;
        }

        public int getOperationType() {
            return operationType;
        }

        public static OperationType fromInt(int value) throws IllegalArgumentException {
            for (OperationType type : OperationType.values()) {
                if (type.getOperationType() == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Unknown protocol type: " + value);
        }

        @Override
        public String toString() {
            return switch (operationType) {
                case 0x0001 -> "QUERY";
                case 0x0002 -> "RESPONSE";
                default -> "Unknown";
            };
        }
    }
}
