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

// Incomplete
const errno (
	EPERM     =  1
	ENOENT    =  2
	ESRCH     =  3
	EINTR     =  4
	EIO       =  5
	ENXIO     =  6
	E2BIG     =  7
	ENOEXEC   =  8
	EBADF     =  9
	ECHILD    = 10
	EAGAIN    = 11
	ENOMEM    = 12
	EACCES    = 13
	EFAULT    = 14
	ENOTBLK   = 15
	EBUSY     = 16
)



func runtime.gcenable()
func runtime.osinit()

func runtime.convT2E(t *_type, elem unsafe.Pointer) (e face)
//func runtime.convT2I(tab *_type, elem unsafe.Pointer) (i iface)
func runtime.convT2I(tab *_type, elem *_elem) (i iface)
func runtime.assertE2T2(typ *byte, iface uintptr/p) (ret any, ok bool)
func runtime.assertI2T2(typ *_type, iface any) (ret any, ok bool)
func runtime.efacethash(i1 uintptr/x) (ret uint32)

func runtime.memhash(p unsafe.Pointer, seed, s uintptr) uintptr/x
func runtime.getitab(inter *interfacetype, typ *_type, canfail bool) *itab

func runtime.memeq(a, b unsafe.Pointer, size uintptr) bool
func runtime.memclr(ptr unsafe.Pointer, n uintptr)


// malloc/dynamic memory

func runtime.mallocinit()
func runtime.mallocgc(size uintptr, typ *_type, needzero bool) unsafe.Pointer
func runtime.newobject(typ *_type) unsafe.Pointer
func runtime.newarray(typ *_type, n int) unsafe.Pointer
func runtime.persistentalloc(size, align uintptr, sysStat *uint64) unsafe.Pointer
func runtime.persistentalloc1(size, align uintptr, sysStat *uint64) unsafe.Pointer
func runtime.nextSample() int32
//func allocm(_p_ *p, fn func()) *m
func runtime.allocm(_p_ *p, fn pfn) *m
func runtime.(h *mheap) alloc_m(npage uintptr, sizeclass int32, large bool) *mspan

func runtime.heapBits.initSpan(s *mspan)
func runtime.recordspan(vh unsafe.Pointer, p unsafe.Pointer)
func runtime.heapBitsSetType~(x, size uintptr, dataSize uintptr, typ *_type)
func runtime.heapBitsBulkBarrier~(p, size uintptr/p)
func progToPointerMask(prog *byte, size uintptr) bitvector
func runtime.runGCProg(prog *byte, trailer, dst *byte, size int) uintptr

func runtime.computeDivMagic(c *class)


func runtime.sysAlloc(uintptr *n) unsafe.Pointer

func runtime.getsig(i uint32) uintptr
func runtime.setsig(i uint32, fn uintptr/p)

func runtime.gogetenv(key string) string
func runtime.GOROOT() string

func runtime.strequal(unsafe.Pointer p, unsafe.Pointer q) bool

func runtime.atomicstorep(ptr unsafe.Pointer, new unsafe.Pointer)

//func StorePointer(addr *unsafe.Pointer, val unsafe.Pointer)
//void sync/atomic.StorePointer(void **addr, void *val)

func runtime.casp(ptr *unsafe.Pointer, old, new unsafe.Pointer) bool
func runtime.casgstatus(gp *g, oldval, newval uint32)

// func mmap(addr unsafe.Pointer, n uintptr, prot, flags, fd int32, off uint32) unsafe.Pointer
func runtime.mmap(addr uintptr, n uintptr, prot/om int32=mmap_prot, flags/x int32, fd int32, off uint32) unsafe.Pointer
//func mmap_fixed(v unsafe.Pointer, n uintptr, prot, flags, fd int32, offset uint32) unsafe.Pointer 
func runtime.mmap_fixed(v unsafe.Pointer, n uintptr, prot/om int32=mmap_prot, flags/x int32, fd int32, offset uint32) unsafe.Pointer

// channels
func runtime.closechan(c *hchan)
func runtime.makechan(t *chantype, size int) *hchan
//func chanrecv(c *hchan, ep unsafe.Pointer, block bool) (selected, received bool)
func runtime.chanrecv(c *hchan, ep unsafe.Pointer, block bool) (selected bool, received bool)
func runtime.chanrecv1(c *hchan, elem unsafe.Pointer)
func runtime.chansend1(c *hchan, elem unsafe.Pointer)

func runtime.GOMAXPROCS(n int) int

// syscalls
func runtime.entersyscall(dummy int32)
func runtime.reentersyscall(pc, sp uintptr/p)
//func Syscall(trap int64, a1, a2, a3 int64) (r1, r2, err int64)
func syscall.Syscall(trap int64, a1 int64=SYSCALL_NO, a2 int64/p, a3 int64) (r1 int64, r2 int64, err int64)
func runtime.exitsyscall(dummy int32)
func runtime.exitsyscallfast() bool
func runtime.asminit~()
func runtime.asmcgocall(fn, arg unsafe.Pointer) int32
func runtime.entersyscallblock(dummy int32)
func syscall.errnoErr(e Errno=errno) error

func runtime.getcallerpc~() uintptr/p
func runtime.getcallersp~(argp unsafe.Pointer) uintptr/p

func syscall.Write(fd int, p []byte) (n int, err error)

func runtime.exit(code int32)
func runtime.sleep(ms int32) int32
func runtime.usleep(usec uint32)
func runtime.futexsleep(addr *uint32, val uint32, ns int64)
func runtime.notetsleep(n *note, ns int64) bool
func runtime.nanotime~() int64
func runtime.unixnanotime() int64
func runtime.timediv(v int64, div int32, rem *int32)
func runtime.timerproc(tb *timersBucket)
func runtime.notetsleep(n *note, ns int64) bool
func runtime.notetsleepg(n *note, ns int64) bool
func runtime.notesleep(n *note)
func runtime.notewakeup(n *note)
func timer.Sleep(d Duration)
func runtime.addtimer(t *timer)
func runtime.deltimer(t *timer) bool

// Errors
func errors.New(text string) error

// Networking
//func epollwait(epfd int32, ev *epollevent, nev, timeout int32) int32
func runtime.epollwait~(epfd int32, ev *epollevent, nev int32, timeout int32) int32
func runtime.netpollready(gpp *guintptr, pd *pollDesc, mode int32)
func runtime.netpoll(block bool) *g
func runtime.netpollinited() bool
func net.IP.IsLoopback() bool
func net.isZeros~(p IP) bool
func net.selfConnect(fd *netFD, err error) bool
func net.LookupPort(network, service string) (port int, err error)
func net.parseIPv4(s string) net.IP
func net.parseIPv6(s string, zoneAllowed bool) (ip net.IP, zone string)
func net.splitHostZone(s string) (host, zone string)
func net.SplitHostPort(hostport string) (host, port string, err error)
func net.last(s string, b byte) int
func net.ResolveTCPAddr(network string, address string) (*net.TCPAddr, error)
func net.absDomainName(b []byte) string
func net.IP.To4() IP
func net.parseLiteralIP(addr string) string
//func (ip IP) String() string
func net.IP.String() string
func net.appendHex(dst []byte, i uint32) []byte
//func net.ipToSockaddr(family int, ip IP, port int, zone string) (syscall.Sockaddr, error)
func syscall.Connect(fd int, sa Sockaddr) (err error)
func net.setDefaultSockopts(s, family, sotype int, ipv6only bool) error

func net.dtoi~(s string) (n int, i int, ok bool)
func net.itoa~(val int) string
func net.uitoa~(val uint) string
func net.xtoi~(s string) (n int, i int, ok bool)

func time.now() (sec int64, nsec int32, mono int64)

func runtime/internal/atomic.Load(ptr *uint32) uint32
//func runtime.memmove~(to *any, frm *any, length uintptr)
func runtime.typedmemmove(t *rtype, dst, src unsafe.Pointer)

func runtime.lock(l *mutex)
func runtime.unlock(l *mutex)
func runtime.futex(addr unsafe.Pointer, op int32, val uint32, ts, addr2 unsafe.Pointer, val3 uint32) int32
func sync.(m *Mutex) Lock()
func sync.(m *Mutex) Unlock()

// Format
func fmt.parsenum(s string, start, end int) (num int, isnum bool, newi int)

func runtime.runqsteal(_p_, p2 *p, stealRunNextG bool) *g
//func runqgrab(_p_ *p, batch *[256]guintptr, batchHead uint32, stealRunNextG bool) uint32
func runtime.runqgrab(_p_ *p, batch *guintptr, batchHead uint32, stealRunNextG bool) uint32
func runtime.runqget(_p_ *p) (gp *g, inheritTime bool)
func runtime.goready(gp *g, traceskip int)
//func mcall(fn func(*g))
func runtime.mcall(fn pfn)

func runtime.return0()
func runtime.adjustsudogs~(gp *g, adjinfo *adjustinfo)
//func systemstack(fn func())
func runtime.systemstack(fn pfn)
func runtime.sigaltstack(new, old *stackt)
func runtime.malg(stacksize int32) *g
func runtime.sigInstallGoHandler~(sig uint32) bool
func runtime.rt_sigaction~(sig uintptr, new, old *sigactiont, size uintptr) int32

func runtime.checkdead()
func runtime.schedule()
func runtime.mput(mp *m)
func runtime.releasep() *p
func runtime.pidleput(_p_ *p)
func runtime.readgstatus(gp *g) uint32
func runtime.mpreinit(mp *m)
func runtime.publicationBarrier~()

func runtime.execute(gp *g, inheritTime bool)
func runtime.procyield(cycles uint32)
func runtime.ready(gp *g, traceskip int, next bool)
//func gopark(unlockf func(*g, unsafe.Pointer) bool, lock unsafe.Pointer, reason string, traceEv byte, traceskip int)
func runtime.gopark(unlockf pfn, lock unsafe.Pointer, reason string, traceEv byte, traceskip int)
func threadentry(v uintptr/p)
func runtime.adjustframe(frame *stkframe, arg unsafe.Pointer) bool

func runtime.findfunc(pc uintptr) funcInfo
func runtime.findmoduledatap(pc uintptr/p) *moduledata
//func runtime.step(p []byte, pc *uintptr, val *int32, first bool) (newp []byte, ok bool)
func runtime.stackmapdata(stkmap *stackmap, n int32) bitvector
func runtime.handoffp(_p_ *p)
//func newm(fn func(), _p_ *p)
func runtime.newm(fn pfn, _p_ *p)
func runtime.acquirep(_p_ *p)
func runtime.acquirep1(_p_ *p)
func runtime.gosave(buf *gobuf)
func runtime.gogo(buf *gobuf)
func runtime.prefetchnta(addr uintptr/p)

// Slices
//func makeslice(et *_type, len, cap int) slice
func runtime.makeslice(et *_type, len, cap int) slice

func runtime\internal\atomic.Load(ptr *uint32) uint32
func runtime\internal\atomic.Load64(ptr *uint64) uint64
func runtime\internal\atomic.Xchg(ptr *uint32, new uint32) uint32

func runtime.mapassign1(t *maptype, h *hmap, key unsafe.Pointer, val unsafe.Pointer)

func runtime.aeshashstr(p unsafe.Pointer, h uintptr) uintptr/x
func runtime.aeshash32(p unsafe.Pointer, h uintptr) uintptr/x
func runtime.aeshash64(p unsafe.Pointer, h uintptr) uintptr/x

// Strings
func strings.IndexByte~(s string, c byte) int
func runtime.findnull(s *byte) int
func runtime.gostring(p *byte) string
func runtime.gostringnocopy(str *byte) string
//func runtime.rawstring(size int) (s string, b []byte)
//func runtime.rawstringtmp(buf *tmpBuf, l int) (s string, b []byte)
func runtime.slicebytetostring(buf *tmpBuf, b []byte) (str string)
func runtime.concatstrings(buf *tmpBuf, a []string) string

// Bytes
func bytes.IndexByte~(s []byte, c byte) int

// Linker
func runtime.vdso_find_version(info *vdso_info, ver *version_key) int32
func runtime.vdso_parse_symbols(info *vdso_info, version int32)
func runtime.vdso_init_from_sysinfo_ehdr(info *vdso_info, hdr *elf64Ehdr)

// Math
func runtime.round2(x int32) int32

// File
func net.(f *file) readLine() (s string, ok bool)
func net.(f *file) getLineFromData() (s string, ok bool)
func os.(f *File) read(b []byte) (n int, err error)
func os.(f *File) Read(b []byte) (n int, err error)
func os.(f *File) Close() error
func os.NewFile(fd uintptr, name string) *File
