package main


import "fmt"
import "net"
import "time"


func Somefunc(hi int) {
	fmt.Println("Somefunc(): input =", hi)
}

func Somefunc2(hi int, hi2 int) {
	fmt.Printf("Somefunc2(): input = %d, %d\n", hi, hi2)
}

func Somefunc3(hi string) int {
	fmt.Printf("Somefunc3(): input = %s; output = 0xdeadbeef\n", hi)
	return 0xdeadbeef
}

func Somefunc4(hi string, hi2 string) int {
	fmt.Printf("Somefunc4(): input = %s | %s; output = 0xc0debabe\n", hi, hi2)
	return 0xc0debabe
}

func Somefunc5(b bool, val int) {
	fmt.Printf("Somefunc5(): input = %v, %v\n", b, val)
	b = !b
}

func Somefunc6(i1 int, i2 uint) {
	fmt.Printf("Somefunc6(): input = %v, %v\n", i1, i2)
}

func Somefunc10(hi int32, hi2 int32, ok bool, hi3 uint32) {
	fmt.Printf("The number is %v\n", hi)
}

func Somefunc11(hi int16, hi2 int16, ok bool, hi3 uint16) {
	fmt.Printf("The number is %v\n", hi)
}

func Somefunc12(hi int16) (string, string) {
	fmt.Printf("The number is %v\n", hi)
	return "hello there", "world!"
}

/*func Somefunc7(iarr []int) {
	fmt.Println("GOT ARRAY: ", iarr)
}

func Somefunc8(c net.Conn) {
	fmt.Println("CONN: ", c)
} */
func TouchConnection(c *net.TCPConn) {
	fmt.Println("We got a connection!")
}

func GetConnection() *net.TCPConn {
	servAddr := "www.google.com:443"
	tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)
	if err != nil {
		return nil
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil
	}

	return conn
}


func main() {
	fmt.Println("GO TEST GO TEST")
	conn := GetConnection()
	TouchConnection(conn)
	fmt.Println("conn = ", conn)
	Somefunc(0x41424344)
	Somefunc2(0x11223344, 0x66778899)
	var ok int = 1
	ok = Somefunc3("abc123")
	fmt.Println(ok)
	Somefunc4("the quick brown fox", "jumps over the lazy dogs")
	Somefunc5(true, 123)
	Somefunc6(0-1, 0xffffffffffffffff)

	Somefunc10(31337, 69, true, 13)
	Somefunc11(31338, 70, false, 31)
	Somefunc12(31339)

	ok = Somefunc3("why")

	fmt.Println("go program will sleep for 10 seconds")
	time.Sleep(10 * time.Second)

/*	arr := []int{666}
	Somefunc7(arr)

	c, err := net.Dial("tcp", "golang.org:http")
	if err != nil {
		fmt.Println("Error establishing TCP connection: ", err)
		return
	}

	fmt.Printf("c = %p\n", c)
	Somefunc8(c) */

}
