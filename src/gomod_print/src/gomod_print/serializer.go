package main

import (
        "fmt"
        "net"
	"strings"
	"strconv"
        "unsafe"
)


func gotrace_print_net__TCPConn(c uintptr) string {
        cc := (*net.TCPConn)(unsafe.Pointer(c))
	desc := "TCPConn(nil)"

	if cc != nil {
		a1 := fmt.Sprintf("%v", cc.LocalAddr())
		a2 := fmt.Sprintf("%v", cc.RemoteAddr())
//	        desc = fmt.Sprintf("[TCPConn] %v <-> %v", cc.LocalAddr().String(), cc.RemoteAddr().String())
	        desc = fmt.Sprintf("(TCPConn: %v <-> %v)", prune_addr(a1), prune_addr(a2))
	}

        return desc
}

func GetConnection() *net.TCPConn {
	servAddr := "www.google.com:443"
	fmt.Println("Resolving")
	tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)
	if err != nil {
		return nil
	}

	fmt.Println("Connecting")
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil
	}

	return conn
}

func prune_addr(astr string) string {
	p1 := strings.Index(astr, "[")
	p2 := strings.Index(astr, "]")
	var is4 bool = true

	if p1 == -1 || p2 == -1 {
		return astr
	}

	astr = strings.TrimSpace(astr[p1+1:p2-0]) + " : " +  strings.TrimSpace(astr[p2+1:])

	if astr[len(astr)-1] == '}' {
		astr = strings.TrimSpace(astr[:len(astr)-1])
	}

	toks := strings.Split(astr, " ")
	astr += fmt.Sprintf(" / %d", len(toks))

	if len(toks) != 6 {
		is4 = false
	} else {

		for i := 0; i < len(toks)-2; i++ {
			num, err := strconv.Atoi(toks[i])

			if err != nil {
				is4 = false
				break
			} else if num < 0 || num > 255 {
				is4 = false
				break
			}

		}

	}

	if is4 {
		astr = strings.Join(toks[0:4], ".") + ":" + toks[5]
	} else {
		astr = strings.Join(toks[0:len(toks)-2], ":") + " : " + toks[len(toks)-1]
	}

	return astr
}

func main() {
//        fmt.Println("Testing 123.")
}
