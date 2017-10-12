package main

import (
        "fmt"
        "net"
        "unsafe"
)

// extern char *gotrace_print_net__TCPConn(unsigned long);
import "C"

//export gotrace_print_net__TCPConn
func gotrace_print_net__TCPConn(c uintptr) *C.char {
        cc := (*net.TCPConn)(unsafe.Pointer(c))
	desc := "TCPConn(nil)"

	if cc != nil {
//	        desc = fmt.Sprintf("[TCPConn] %v <-> %v", cc.LocalAddr().String(), cc.RemoteAddr().String())
	        desc = fmt.Sprintf("[TCPConn] %v <-> %v", cc.LocalAddr(), cc.RemoteAddr())
	}

        return C.CString(desc)
}

func main() {
//        fmt.Println("Testing 123.")
}
