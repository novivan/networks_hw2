package main

import (
	"fmt"

	"github.com/novivan/networks_hw2/internal/dialoger"
)

func main() {
	d := dialoger.NewDialoger()
	err := d.Run()
	if err != nil {
		fmt.Printf("Работа приложения завершилась с ошибкой: %v\n", err)
	} else {
		fmt.Println("Работа приложения завершилась успешно!")
	}
}
