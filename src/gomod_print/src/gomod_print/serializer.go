package main

import (
        "fmt"
        "net"
	"strings"
	"strconv"
        "unsafe"
)

type _stack struct {
	lo uintptr
	hi uintptr
}

type _stkbar struct {
	savedLRPtr uintptr
	savedLRVal uintptr
}

type _gobuf struct {
	sp uintptr
	pc uintptr
	g uintptr
	ctxt unsafe.Pointer
//	ret sys.Uintreg
	ret uint64
	lr uintptr
	bp uintptr
}

type _g struct {
        _stack _stack
	stackguard0 uintptr
	stackguard1 uintptr
//	_panic *_panic
	_panic uintptr
//	_defer *_defer
	_defer uintptr
	m *_m
	stackAlloc uintptr
	sched _gobuf
	syscallsp uintptr
	syscallpc uintptr
	stkbar []_stkbar
	stkbarPos uintptr
	stktopsp uintptr
	param unsafe.Pointer
}

type _m struct {
	g0 *_g
	morebuf _gobuf
	divmod uint32
	procid uint64
	gsignal *_g
}

func gotrace_print_g_area(g uintptr) string {
	__g := (*_g)(unsafe.Pointer(g))

	return fmt.Sprintf("{ m = %v, syscallpc = %v }", unsafe.Pointer(__g.m), unsafe.Pointer(__g.syscallpc))
}

func gotrace_print_m_area(m uintptr) string {
	__m := (*_m)(unsafe.Pointer(m))

	return fmt.Sprintf("{ g0 = %v, procid = %v }", unsafe.Pointer(__m.g0), __m.procid)
	return fmt.Sprintf("hehe %p", __m)
	return fmt.Sprintf("xyz")
}


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
