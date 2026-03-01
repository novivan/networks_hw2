package dialoger

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/novivan/networks_hw2/internal/pcap"
)

type Dialoger struct {
	processer pcap.PCAP_processer
}

func NewDialoger() Dialoger {
	return Dialoger{
		processer: pcap.NewPCAP_processer(),
	}
}

func (d Dialoger) Run() error {
	var wanna_break bool = false
	reader := bufio.NewReader(os.Stdin)
	for iteration := 0; true; iteration++ {
		if iteration == 0 {
			fmt.Println(introduction)
		}
		var inp, _ = reader.ReadString('\n')
		inp = strings.Trim(inp, "\n\t\r ")
		// пока что почти все заглушим
		switch inp {
		case "capture":
			fmt.Println("capturing ARPs...")
			_, err := d.processer.Handle_all_packets()
			if err != nil {
				fmt.Printf("Error capturing packets: %v\n", err)
			}
		case "router_mac":
			fmt.Println("finding router mac address...")
		case "exit":
			fmt.Println("exiting...")
			wanna_break = true
		case "help":
			fmt.Println(introduction)
		default:
			if strings.HasPrefix(inp, STATISTICS_PREFFIX) {
				var useful_info string = inp[len(STATISTICS_PREFFIX):]

				seconds, err := strconv.Atoi(strings.Split(useful_info, " ")[0])
				if err != nil {
					fmt.Println("Неправильно введена команда")
					fmt.Printf("\tОшибка: %w\n", err)
					fmt.Println("\tДля просмотра списка команда и формата введите \"help\" + Enter")
				}
				fmt.Printf("Собираю статистику на протяжении %d секунд...\n", seconds)
			} else {
				fmt.Println("Команда введена неправильно. Для просмотра доступных комманд введите \"help\" + Enter")
			}
		}
		if wanna_break {
			break
		}
	}
	return nil
}
