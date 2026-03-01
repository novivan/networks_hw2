package pcap

import (
	"fmt"

	"github.com/alicebob/pcap"
)

type PCAP_processer struct{}

func NewPCAP_processer() PCAP_processer {
	return PCAP_processer{}
}

func (p PCAP_processer) Handle_all_packets() (string, error) {
	device := "en0"
	filter := "arp"

	handle, err := pcap.OpenLive(device, 1600, true, 0)
	if err != nil {
		return "", fmt.Errorf("An error occured while opening device %s: %v\n", device, err)
	}
	defer handle.Close()

	err = handle.SetFilter(filter)
	if err != nil {
		return "", fmt.Errorf("An error occured while setting filter for packets: %v\n", err)
	}

	fmt.Println("Start catching ARP packets. waiting...")

	// packetSource := pcap.PacketSource(handle, handle.Linktype())

	//for packet := range packetSource.Packets() {
	for packet := handle.Next(); packet != nil; packet = handle.Next() {
		if packet == nil {
			break
		}
		fmt.Printf("\n--- ARP-пакет ---\n")
		fmt.Printf("Время: %v\n", packet.Time)
		fmt.Printf("Длина: %d байт\n", packet.Len)

		fmt.Printf("Сырые данные (первые 64 байта): % x\n", packet.Data)
	}
	return "", nil
}
