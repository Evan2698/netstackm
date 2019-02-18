package common

import (
	"fmt"
	"net"
	"strings"
)

// GenerateUniqueKey ...
func GenerateUniqueKey(src, dst net.IP, srcp, dstp uint16) string {
	return strings.Join([]string{
		src.String(),
		fmt.Sprintf("%d", srcp),
		dst.String(),
		fmt.Sprintf("%d", dstp),
	}, "<->")
}
