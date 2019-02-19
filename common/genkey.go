package common

import (
	"fmt"
	"net"
	"strings"
)

// GenerateUniqueKey ...
func GenerateUniqueKey(src, dst net.IP, srcp, dstp uint16) string {
	a := net.JoinHostPort(src.String(), fmt.Sprintf("%d", srcp))
	b := net.JoinHostPort(dst.String(), fmt.Sprintf("%d", dstp))
	return strings.Join([]string{
		a,
		b,
	}, "<->")
}
