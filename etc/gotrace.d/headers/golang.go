// This is obviously not really golang code;
// there is still work to do with porting the C grammar over.

const mmap_prot (
	PROT_NONE      = 0x0
	PROT_READ      = 0x1
	PROT_WRITE     = 0x2
	PROT_EXEC      = 0x4
	PROT_SEM       = 0x8
	PROT_GROWSDOWN = 0x01000000
	PROT_GROWSUP   = 0x02000000
)


func runtime.gcenable()
func runtime.osinit()

//func convT2E(t *_type, elem unsafe.Pointer) (e eface)
func runtime.convT2E(t *_type, elem unsafe.Pointer) elem
//func assertE2T2(typ *byte, iface any) (ret any, ok bool)
func runtime.assertE2T2(typ *byte, iface uintptr) (ret, bool)
//func assertI2T2(typ *byte, iface any) (ret any, ok bool)
func runtime.assertI2T2(typ *byte, iface uintptr) ret
//func efacethash(i1 any) (ret uint32)
func runtime.efacethash/x(i1 uintptr) uint32

//func memhash(p unsafe.Pointer, seed, s uintptr) uintptr
func runtime.memhash/x(p uintptr, seed uintptr, s uintptr) uintptr
//func getitab(inter *interfacetype, typ *_type, canfail bool) *itab {
func runtime.getitab(inter *interfacetype, typ *_type, canfail bool) itab


// value

//func typedmemmove(t *rtype, dst, src unsafe.Pointer)
func runtime.typedmemmove(t *rtype, dst unsafe.Pointer, src unsafe.Pointer)

// malloc/dynamic memory

func runtime.mallocinit()
func runtime.mallocgc(size uintptr, typ *_typ, needzero bool) unsafe.Pointer
func runtime.newobject(typ *_type) unsafe.Pointer
func runtime.newarray(typ *_type, n int) unsafe.Pointer
//func persistentalloc(size, align uintptr, sysStat *uint64) unsafe.Pointer {
func runtime.persistentalloc(size uintptr, align uintptr, sysStat *uint64) unsafe.Pointer
//func persistentalloc1(size, align uintptr, sysStat *uint64) unsafe.Pointer {
func runtime.persistentalloc1(size uintptr, align uintptr, sysStat *uint64) unsafe.Pointer
func runtime.nextSample() int32

func runtime.heapBits.initSpan(s *mspan)
//func heapBitsSetType(x, size, dataSize uintptr, typ *_type)
func runtime.heapBitsSetType(x uintptr, size uintptr, dataSize uintptr, typ *_type)
func progToPointerMask(prog *byte, size uintptr) bitvector
//func runGCProg(prog, trailer, dst *byte, size int) uintptr
func runtime.runGCProg(prog *byte, trailer *byte, dst *byte, size int) uintptr


func runtime.sysAlloc(uintptr *n) unsafe.Pointer

func runtime.getsig(i uint32) uintptr
func runtime.setsig(i uint32, fn uintptr/p)

func runtime.gogetenv(key string) string
func runtime.GOROOT() string

int runtime.strequal(unsafe.Pointer p, unsafe.Pointer q)

func runtime.atomicstorep(ptr unsafe.Pointer, new unsafe.Pointer)

//func StorePointer(addr *unsafe.Pointer, val unsafe.Pointer)
//void sync/atomic.StorePointer(void **addr, void *val)

//func casp(ptr *unsafe.Pointer, old, new unsafe.Pointer) bool
func runtime.casp(ptr *unsafe.Pointer, old unsafe.Pointer, new unsafe.Pointer) bool

// func mmap(addr unsafe.Pointer, n uintptr, prot, flags, fd int32, off uint32) unsafe.Pointer
func runtime.mmap(addr uintptr, n uintptr, prot/om int32=mmap_prot, flags/x int32, fd int32, off uint32) unsafe.Pointer
//func mmap_fixed(v unsafe.Pointer, n uintptr, prot, flags, fd int32, offset uint32) unsafe.Pointer 
func runtime.mmap_fixed(v unsafe.Pointer, n uintptr, prot/om int32=mmap_prot, flags/x int32, fd int32, offset uint32) unsafe.Pointer

// channels
func runtime.closechan(c *hchan)
//func makechan(t *chantype, size int) *hchan
func runtime.makechan(t *chantype, size int) hchan
//func chanrecv(c *hchan, ep unsafe.Pointer, block bool) (selected, received bool)
func runtime.chanrecv(c *hchan, ep unsafe.Pointer, block bool) bool
func runtime.chanrecv1(c *hchan, elem unsafe.Pointer)
func runtime.chansend1(c *hchan, elem unsafe.Pointer)

func runtime.GOMAXPROCS(n int) int

// syscalls
func runtime.entersyscall(dummy int32)
//func Syscall(trap int64, a1, a2, a3 int64) (r1, r2, err int64)
func syscall.Syscall(trap int64, a1 int64=SYSCALL_NO, a2 int64/p, a3 int64) r1
func runtime.exitsyscall(dummy int32)
func runtime.exitsyscallfast() bool
//func asmcgocall(fn, arg unsafe.Pointer) int32
func runtime.asmcgocall(fn unsafe.Pointer, arg unsafe.Pointer) int32

func runtime.getcallerpc/p() uintptr
func runtime.getcallersp/p(argp unsafe.Pointer) uintptr

//func Write(fd int, p []byte) (n int, err error)
int syscall.Write(fd int, p *byte)

func runtime.exit(code int32)
func runtime.sleep(ms int32) int32
func runtime.usleep(usec uint32)
func runtime.futexsleep(addr *uint32, val uint32, ns int64)
func runtime.notetsleep(n *note, ns int64) bool
func runtime.nanotime() int64
func runtime.timediv(v int64, div int32, rem *int32)
func runtime.timerproc(tb *timersBucket)

// Errors
func errors.New(text string) error

// Networking
//func runtime.netpoll(block bool) *g
func runtime.netpoll(block bool) g

func runtime/internal/atomic.Load(ptr *uint32) uint32
func runtime.memmove(to *any, frm *any, length uintptr)

func runtime.lock(l *mutex)
func runtime.unlock(l *mutex)
//func futex(addr unsafe.Pointer, op int32, val uint32, ts, addr2 unsafe.Pointer, val3 uint32) int32
func runtime.futex(addr unsafe.Pointer, op int32, val uint32, ts unsafe.Pointer, addr2 unsafe.Pointer, val3 uint32) int32

func runtime.gogo(buf *gobuf)

// Format
//func parsenum(s string, start, end int) (num int, isnum bool, newi int
func fmt.parsenum(s string, start int, end int) int

//func runqsteal(_p_, p2 *p, stealRunNextG bool) *g
func runtime.runqsteal(_p_ *p, p2 *p, stealRunNextG bool) g
//func runqgrab(_p_ *p, batch *[256]guintptr, batchHead uint32, stealRunNextG bool) uint32
func runtime.runqgrab(_p_ *p, batch *guintptr, batchHead uint32, stealRunNextG bool) uint32
//func runqget(_p_ *p) (gp *g, inheritTime bool)
func runtime.runqget(_p_ *p) (g, inheritTime)

func runtime.return0()
//func systemstack(fn func())
func runtime.systemstack(func pfn)

func runtime.checkdead()
func runtime.schedule()
func runtime.mput(mp *m)
//func releasep() *p
func runtime.releasep() p
//func pidleput(_p_ *p
func runtime.pidleput(_p_ *p)
func runtime.readgstatus(gp *g) uint32
func runtime.execute(gp *g, inheritTime bool)

// Slices
//func makeslice(et *_type, len, cap int) slice
func runtime.makeslice(et *_type, len int, cap int) slice

// Strings
func strings.IndexByte(s string, c byte)

// Network
func runtime.netpollinited() bool
func net.selfConnect(fd *netFD, err error) bool
