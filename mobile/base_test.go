package mobile

import (
	"testing"
	"time"

	"github.com/Evan2698/netstackm/tun"
)

func Test_Main(t *testing.T) {

	file, err := tun.Open("tun0")
	if err != nil {
		t.Error("can not open tun device", err)
		return
	}

	StartService(file, "127.0.0.1:9998", "1.0.0.1")

	time.Sleep(time.Minute * 2)
	StopService()

	var systemsignal = make(chan int, 2)
	<-systemsignal

}
