package main

import (
	"fmt"

	"github.com/Evan2698/netstackm/mobile"
	"github.com/Evan2698/netstackm/tun"
)

func main() {
	file, err := tun.Open("tun0")
	if err != nil {

		fmt.Println(err)

		return
	}

	mobile.StartService(file, "127.0.0.1:9998", "114.114.114.114")

	var systemsignal = make(chan int, 2)
	<-systemsignal
}
