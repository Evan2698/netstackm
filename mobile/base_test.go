package mobile

import (
	"testing"

	"github.com/Evan2698/netstackm/tun"
)

func Test_Main(t *testing.T) {

	file, err := tun.Open("tun0")
	if err != nil {
		t.Error("can not open tun device", err)
		return
	}

	StartService(file, "127.0.0.1:9998", "114.114.114.114")

	var systemsignal = make(chan int, 2)
	<-systemsignal

}
