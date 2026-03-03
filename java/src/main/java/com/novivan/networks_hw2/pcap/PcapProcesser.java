package com.novivan.networks_hw2.pcap;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.pcap4j.core.PcapNativeException;

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
    private static final int packetsToCatch = 7;
    
    private PcapHandle sharedHandle = null;
    private PcapNetworkInterface nif = null;

    //размеры кусков arp-пакета (в байтах)
    private static final int HTYPE_SIZE = 2;
    private static final int PTYPE_SIZE = 2;
    private static final int HLEN_SIZE = 1;
    private static final int PLEN_SIZE = 1;
    private static final int OPERATION_SIZE = 2;


    public PcapProcesser() throws Exception {
        nif = Pcaps.getDevByName(DEVICE); // писал на маке, сделал под него
        if (nif == null) {
            throw new Exception("Сетевой интерфейс не найден");
        }
        sharedHandle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT);
    }
    
    public void close() {
        if (sharedHandle != null) {
            sharedHandle.close();
            sharedHandle = null;
        }
    }

    public String handleAllPackets() throws Exception {
        if (sharedHandle == null) {
            throw new Exception("PcapHandle не инициализирован");
        }
        
        sharedHandle.setFilter(FILTER, BpfProgram.BpfCompileMode.OPTIMIZE);

            System.out.println("Захват ARP-пакетов...");

            System.out.println("");

        sharedHandle.loop(packetsToCatch, (PacketListener) (packet) -> {
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
                System.out.println("");
            });
        System.out.println("Установленное кол-во пакетов(" + packetsToCatch + ") получено! Операция завершена");
        return null;
    }

    public String getRouterMac(String targetIp) throws Exception {
        if (sharedHandle == null) {
            throw new Exception("PcapHandle не инициализирован");
        }

        NetworkInterface netIf = NetworkInterface.getByName(DEVICE);
        byte[] ourMac = netIf.getHardwareAddress();
        if (ourMac == null) {
            System.err.println("Не удалось получить MAC-адрес интерфейса");
            return null;
        }

        InetAddress ourIp = null;
        var addresses = netIf.getInetAddresses();
        while (addresses.hasMoreElements()) {
            InetAddress addr = addresses.nextElement();
            if (addr.getAddress().length == 4) { // IPv4
                ourIp = addr;
                break;
            }
        }
        if (ourIp == null) {
            System.err.println("Не удалось получить IP-адрес интерфейса");
            return null;
        }

        InetAddress targetInetAddr = InetAddress.getByName(targetIp);
        byte[] targetIpBytes = targetInetAddr.getAddress();

        byte[] arpRequest = buildArpRequest(ourMac, ourIp.getAddress(), targetIpBytes);

        System.out.println("Отправка ARP-запроса для IP: " + targetIp);
        System.out.println("Наш MAC: " + formatMacBytes(ourMac));
        System.out.println("Наш IP: " + ourIp.getHostAddress());

        AtomicReference<String> resultMac = new AtomicReference<>(null);

        sharedHandle.setFilter("arp and arp[6:2] = 2", BpfProgram.BpfCompileMode.OPTIMIZE);

        sharedHandle.sendPacket(arpRequest);
            System.out.println("ARP-запрос отправлен!");

            long startTime = System.currentTimeMillis();
            while (System.currentTimeMillis() - startTime < 5000) {
                try {
                    var packet = sharedHandle.getNextPacketEx();
                    byte[] raw = packet.getRawData();
                    if (raw.length >= 42) {
                        int operation = ((raw[20] & 0xFF) << 8) | (raw[21] & 0xFF);
                        if (operation == 2) {
                            byte[] senderIp = Arrays.copyOfRange(raw, 28, 32);
                            if (Arrays.equals(senderIp, targetIpBytes)) {
                                byte[] senderMac = Arrays.copyOfRange(raw, 22, 28);
                                resultMac.set(formatMacBytes(senderMac));
                                System.out.println("\nПолучен ARP-ответ!");
                                System.out.println("MAC-адрес " + targetIp + ": " + resultMac.get());
                                break;
                            }
                        }
                    }
                } catch (Exception e) {}
            }

            if (resultMac.get() == null) {
                System.out.println("Не удалось получить ARP-ответ в течение 5 секунд");
            }

        // Восстанавливаем исходный фильтр
        sharedHandle.setFilter(FILTER, BpfProgram.BpfCompileMode.OPTIMIZE);

        return resultMac.get();
    }

    private byte[] buildArpRequest(byte[] senderMac, byte[] senderIp, byte[] targetIp) {
        byte[] packet = new byte[42];

        Arrays.fill(packet, 0, 6, (byte) 0xFF);

        System.arraycopy(senderMac, 0, packet, 6, 6);

        packet[12] = 0x08;
        packet[13] = 0x06;
        packet[14] = 0x00;
        packet[15] = 0x01;
        packet[16] = 0x08;
        packet[17] = 0x00;
        packet[18] = 0x06;
        packet[19] = 0x04;
        packet[20] = 0x00;
        packet[21] = 0x01;

        System.arraycopy(senderMac, 0, packet, 22, 6);
        System.arraycopy(senderIp, 0, packet, 28, 4);
        Arrays.fill(packet, 32, 38, (byte) 0x00);
        System.arraycopy(targetIp, 0, packet, 38, 4);

        return packet;
    }

    private static String formatMacBytes(byte[] mac) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format("%02x", mac[i] & 0xFF));
            if (i < mac.length - 1) sb.append(":");
        }
        return sb.toString();
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

    public static class NetworkStatistics {
        public int totalEthernetFrames = 0;
        public int totalArpPackets = 0;
        public Set<String> uniqueMacAddresses = new HashSet<>();
        public int broadcastEthernetFrames = 0;
        public int broadcastArpPackets = 0;
        public int gratuitousArpRequests = 0;
        public int arpRequestResponsePairs = 0;
        public long bytesWithRouter = 0;
        
        public Map<String, Long> pendingArpRequests = new HashMap<>();
        
        public String routerMac = null;
        public String ourMac = null;
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("\n");
            sb.append("         СТАТИСТИКА СЕТИ\n");
            sb.append("\n");
            
            sb.append("1. Ethernet фреймов передано: ").append(totalEthernetFrames).append("\n");
            sb.append("   ARP пакетов: ").append(totalArpPackets).append("\n\n");
            
            sb.append("2. Уникальных MAC-адресов обнаружено: ").append(uniqueMacAddresses.size()).append("\n");
            sb.append("   Список MAC-адресов:\n");
            for (String mac : uniqueMacAddresses) {
                sb.append("\t - ").append(mac).append("\n");
            }
            sb.append("\n");
            
            sb.append("3. Широковещательных Ethernet сообщений: ").append(broadcastEthernetFrames).append("\n");
            sb.append("   Из них с ARP: ").append(broadcastArpPackets).append("\n\n");
            
            sb.append("4. Gratuitous ARP Requests: ").append(gratuitousArpRequests).append("\n\n");
            
            sb.append("5. Пар ARP request/response: ").append(arpRequestResponsePairs).append("\n\n");
            
            sb.append("6. Объём данных между устройством и роутером: ").append(bytesWithRouter).append(" байт\n");
            
            sb.append("\n");
            return sb.toString();
        }
    }

    public NetworkStatistics collectStatistics(int seconds, String routerIp) throws Exception {
        if (sharedHandle == null) {
            throw new Exception("PcapHandle не инициализирован");
        }

        NetworkStatistics stats = new NetworkStatistics();
        
        NetworkInterface netIf = NetworkInterface.getByName(DEVICE);
        byte[] ourMacBytes = netIf.getHardwareAddress();
        if (ourMacBytes != null) {
            stats.ourMac = formatMacBytes(ourMacBytes);
        }
        
        String routerMac = null;
        if (routerIp != null && !routerIp.isEmpty()) {
            System.out.println("Определяем MAC-адрес роутера...");
            routerMac = getRouterMac(routerIp);
            stats.routerMac = routerMac;
            if (routerMac != null) {
                System.out.println("MAC роутера: " + routerMac);
            }
        }
        
        final String finalRouterMac = routerMac;
        final long endTime = System.currentTimeMillis() + (seconds * 1000L);

        System.out.println("\nСбор статистики в течение " + seconds + " секунд...\n");

        sharedHandle.setFilter("", BpfProgram.BpfCompileMode.OPTIMIZE);
            
            final long[] endTimeHolder = {endTime};
            final NetworkStatistics finalStats = stats;
            final String fRouterMac = finalRouterMac;
            
            Thread captureThread = new Thread(() -> {
                try {
                    sharedHandle.loop(-1, (PacketListener) (packet) -> {
                        if (System.currentTimeMillis() >= endTimeHolder[0]) {
                            try {
                                sharedHandle.breakLoop();
                            } catch (Exception e) {
                                // Игнорируем исключения при breakLoop
                            }
                            return;
                        }
                        
                        try {
                            byte[] raw = packet.getRawData();
                            if (raw == null || raw.length < 14) return;
                            
                            finalStats.totalEthernetFrames++;
                            
                            String dstMac = formatMacBytes(Arrays.copyOfRange(raw, 0, 6));
                            String srcMac = formatMacBytes(Arrays.copyOfRange(raw, 6, 12));
                            
                            finalStats.uniqueMacAddresses.add(srcMac);
                            if (!dstMac.equals("ff:ff:ff:ff:ff:ff")) {
                                finalStats.uniqueMacAddresses.add(dstMac);
                            }
                            
                            boolean isBroadcast = dstMac.equals("ff:ff:ff:ff:ff:ff");
                            if (isBroadcast) {
                                finalStats.broadcastEthernetFrames++;
                            }
                            
                            int etherType = ((raw[12] & 0xFF) << 8) | (raw[13] & 0xFF);
                            boolean isArp = (etherType == 0x0806);
                            
                            if (isArp && raw.length >= 42) {
                                finalStats.totalArpPackets++;
                                
                                if (isBroadcast) {
                                    finalStats.broadcastArpPackets++;
                                }
                                
                                int operation = ((raw[20] & 0xFF) << 8) | (raw[21] & 0xFF);
                                String senderMac = formatMacBytes(Arrays.copyOfRange(raw, 22, 28));
                                String senderIp = formatIpBytes(Arrays.copyOfRange(raw, 28, 32));
                                String targetMac = formatMacBytes(Arrays.copyOfRange(raw, 32, 38));
                                String targetIp = formatIpBytes(Arrays.copyOfRange(raw, 38, 42));
                                
                                if (operation == 1 && senderIp.equals(targetIp)) {
                                    finalStats.gratuitousArpRequests++;
                                }
                                
                                if (operation == 1) {
                                    String key = senderIp + "->" + targetIp;
                                    finalStats.pendingArpRequests.put(key, System.currentTimeMillis());
                                } else if (operation == 2) {
                                    String key = targetIp + "->" + senderIp;
                                    if (finalStats.pendingArpRequests.containsKey(key)) {
                                        long requestTime = finalStats.pendingArpRequests.get(key);
                                        if (System.currentTimeMillis() - requestTime < 5000) {
                                            finalStats.arpRequestResponsePairs++;
                                        }
                                        finalStats.pendingArpRequests.remove(key);
                                    }
                                }
                            }
                            
                            if (fRouterMac != null && finalStats.ourMac != null) {
                                if ((srcMac.equals(fRouterMac) && dstMac.equals(finalStats.ourMac)) ||
                                    (srcMac.equals(finalStats.ourMac) && dstMac.equals(fRouterMac))) {
                                    finalStats.bytesWithRouter += raw.length;
                                }
                            }
                        } catch (Exception e) {
                            // Игнорируем исключения при обработке пакетов
                        }
                    });
                } catch (Exception e) {
                    // Игнорируем исключения в потоке захвата
                }
            });
            
            captureThread.start();
            
            Thread.sleep(seconds * 1000L + 500);
            
            try {
                sharedHandle.breakLoop();
            } catch (Exception e) {
                // Игнорируем исключения при breakLoop
            }
            
            captureThread.join(2000);

        // Восстанавливаем исходный фильтр
        sharedHandle.setFilter(FILTER, BpfProgram.BpfCompileMode.OPTIMIZE);
        
        return stats;
    }
    
    private static String formatIpBytes(byte[] ip) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ip.length; i++) {
            sb.append(ip[i] & 0xFF);
            if (i < ip.length - 1) sb.append(".");
        }
        return sb.toString();
    }
}
