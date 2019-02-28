# netstackms
simple netstack for android or ios 


# How to build

cd $GOPATH/src
go get github.com/Evan2698/chimney/cmd/client
git clone https://github.com/Evan2698/netstackm.git
gomobile bind -target=android  -ldflags="-s -w" github.com/Evan2698/chimney/android

BTW: gomobile install:
https://godoc.org/golang.org/x/mobile/cmd/gomobile


# How to use

call 
** func StartNetstackService(fd int, socks string, dns string)
to start service.

call 
** StopNetStackService() to stop service .  

gomobile automatically generates java code.

# References
https://github.com/dutchcoders/netstack

https://github.com/FlowerWrong/tun2socks

https://github.com/yinghuocho/gotun2socks
