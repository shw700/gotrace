// This is obviously not really golang code;
// there is still work to do with porting the C grammar over.

//#define GOVERSION	1.7.0

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



func runtime.osinit()
func runtime.schedinit()
func runtime.gcinit()
func runtime.gcenable()
func runtime.getproccount() int32
func runtime.procresize(nprocs int32) *p
func runtime.sysargs(argc int32, argv **byte)
func runtime.args(c int32, v **byte)
func runtime.check()
func runtime.checkASM() bool
func runtime.initSizes()
func runtime.goargs()
func runtime.init()
func runtime.goexit0(gp *g)

func runtime.convT2E(t *_type, elem unsafe.Pointer) (e face)
//func runtime.convT2I(tab *_type, elem unsafe.Pointer) (i iface)
func runtime.convT2I(tab *_type, elem *_elem) (i iface)
func runtime.assertE2T2(typ *byte, iface uintptr/p) (ret any, ok bool)
func runtime.assertI2T2(typ *_type, iface any) (ret any, ok bool)
func runtime.efacethash(i1 uintptr/x) (ret uint32)
func runtime.ifacethash(i iface) uint32
func runtime.ifaceeq(x, y iface) bool
func runtime.typ2Itab(t *_type, inter *interfacetype, cache **itab) *itab

func runtime.memhash(p unsafe.Pointer, seed, s uintptr) uintptr/x
func runtime.getitab(inter *interfacetype, typ *_type, canfail bool) *itab

func runtime.memeq(a, b unsafe.Pointer, size uintptr) bool
func runtime.memequal64(p, q unsafe.Pointer) bool
func runtime.memclr(ptr unsafe.Pointer, n uintptr)
func runtime.memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr)

func runtime.printstring(s string)
func runtime.printint(v int64)
func runtime.printuint(v uint64)
func runtime.printhex(v uint64)
func runtime.gwrite(b []byte)
func runtime.writeErr(b []byte)
func runtime.printlock()
func runtime.printunlock()
func runtime.write(fd uintptr, p unsafe.Pointer, n int32) int32
func runtime.startpanic()
func runtime.startpanic_m()
func runtime.dopanic(unused int)
func runtime.dopanic_m(gp *g, pc, sp uintptr/p)
func runtime.freezetheworld()
func runtime.throw(s string)
func runtime.tracebackinit()
func runtime.traceback(pc, sp, lr uintptr/p, gp *g)
func runtime.traceback1(pc, sp, lr uintptr/p, gp *g, flags uint)
func runtime.haveexperiment(name string) bool


// malloc/dynamic memory

func runtime.sysReserve(v unsafe.Pointer, n uintptr, reserved *bool) unsafe.Pointer
func runtime.minit()
func runtime.mallocinit()
func runtime.mallocgc(size uintptr, typ *_type, needzero bool) unsafe.Pointer
func runtime.newobject(typ *_type) unsafe.Pointer
func rawmem(size uintptr) unsafe.Pointer
func runtime.newarray(typ *_type, n int) unsafe.Pointer
func runtime.persistentalloc(size, align uintptr, sysStat *uint64) unsafe.Pointer
func runtime.persistentalloc1(size, align uintptr, sysStat *uint64) unsafe.Pointer
func runtime.nextSample() int32
//func allocm(_p_ *p, fn func()) *m
func runtime.allocm(_p_ *p, fn pfn) *m
func runtime.mcommoninit(mp *m)
func runtime.startm(_p_ *p, spinning bool)
func runtime.allocmcache() *mcache
func runtime.(h *mheap) alloc_m(npage uintptr, sizeclass int32, large bool) *mspan
func runtime.(h *mheap) allocStack(npage uintptr)
func runtime.(h *mheap) freeSpanLocked(s *mspan, acctinuse, acctidle bool, unusedsince int64)
func runtime.(h *mheap) allocSpanLocked(npage uintptr) *mspan
func runtime.(span *mspan) init(start pageID, npages uintptr)
func runtime.(list *mSpanList) insert(span *mspan)
func runtime.(list *mSpanList) remove(span *mspan)
func runtime.bestFit(list *mSpanList, npage uintptr, best *mspan) *mspan
func runtime.addspecial(p unsafe.Pointer, s *special) bool
func runtime.removespecial(p unsafe.Pointer, kind uint8) *special

func runtime.heapBits.initSpan(s *mspan)
func runtime.recordspan(vh unsafe.Pointer, p unsafe.Pointer)
func runtime.heapBitsSetType(x, size uintptr, dataSize uintptr, typ *_type)
func runtime.heapBitsBulkBarrier(p, size/d uintptr)
func progToPointerMask(prog *byte, size uintptr) bitvector
func runtime.runGCProg(prog *byte, trailer, dst *byte, size int) uintptr

func runtime.computeDivMagic~(c *class)

func runtime.sysAlloc(uintptr *n) unsafe.Pointer

func runtime.getsig(i uint32) uintptr
func runtime.setsig(i uint32, fn uintptr/p)

func runtime.gogetenv(key string) string
func runtime.copyenv()
func runtime.goenvs()
func runtime.goenvs_unix()
func runtime.GOROOT() string
func os.Getenv(key string) string

func runtime.strequal(unsafe.Pointer p, unsafe.Pointer q) bool

// Atomic operations
func runtime.testAtomic64()
func runtime.atomicstorep(ptr unsafe.Pointer, new unsafe.Pointer)
func sync\atomic.LoadPointer(addr *unsafe.Pointer) unsafe.Pointer
func sync\atomic.LoadUint32(addr *uint32) uint32
func sync\atomic.LoadUint64(addr *uint64) uint64
func sync\atomic.LoadUintptr(addr *uintptr) uintptr/p
func sync\atomic.StorePointer(addr *unsafe.Pointer, val unsafe.Pointer)
func sync\atomic.StoreInt32(addr *int32, val int32)
func sync\atomic.StoreUint32(addr *uint32, val uint32)
func sync\atomic.AddInt32(addr *int32, delta int32) (new int32)
func sync\atomic.AddUint32(addr *uint32, delta uint32) (new uint32)
func sync\atomic.CompareAndSwapInt32(addr *int32, old, new int32) (swapped bool)
func sync\atomic.CompareAndSwapInt64(addr *int64, old, new int64) (swapped bool)
func sync\atomic.CompareAndSwapUint32(addr *uint32, old, new uint32) (swapped bool)
func sync\atomic.CompareAndSwapUint64(addr *uint64, old, new uint64) (swapped bool)
func sync\atomic.CompareAndSwapUintptr(addr *uintptr, old, new uintptr) (swapped bool)
func sync\atomic.CompareAndSwapPointer(addr *unsafe.Pointer, old, new unsafe.Pointer) (swapped bool)
func runtime\internal\atomic.Store~(ptr *uint32, val uint32)
func runtime\internal\atomic.Xadd~(ptr *uint32, delta int32) uint32
func runtime\internal\atomic.Xadd64~(ptr *uint64, delta int64) uint64

func runtime.casp(ptr *unsafe.Pointer, old, new unsafe.Pointer) bool
func runtime.casgstatus(gp *g, oldval, newval uint32)

// func mmap(addr unsafe.Pointer, n uintptr, prot, flags, fd int32, off uint32) unsafe.Pointer
func runtime.mmap(addr uintptr, n uintptr, prot/om int32=mmap_prot, flags/x int32, fd int32, off uint32) unsafe.Pointer
//func mmap_fixed(v unsafe.Pointer, n uintptr, prot, flags, fd int32, offset uint32) unsafe.Pointer 
func runtime.mmap_fixed(v unsafe.Pointer, n uintptr, prot/om int32=mmap_prot, flags/x int32, fd int32, offset uint32) unsafe.Pointer
func runtime.callCgoMmap(addr unsafe.Pointer, n uintptr, prot, flags, fd int32, off uint32) uintptr/p

// channels
func runtime.closechan(c *hchan)
func runtime.makechan(t *chantype, size int) *hchan
//func chanrecv(c *hchan, ep unsafe.Pointer, block bool) (selected, received bool)
func runtime.chanrecv(c *hchan, ep unsafe.Pointer, block bool) (selected bool, received bool)
func runtime.chanrecv1(c *hchan, elem unsafe.Pointer)
func runtime.chansend1(c *hchan, elem unsafe.Pointer)
func runtime.chansend(t *chantype, c *hchan, ep unsafe.Pointer, block bool, callerpc uintptr/p) bool
func runtime.sendDirect(t *_type, sg *sudog, src unsafe.Pointer)
// func send(c *hchan, sg *sudog, ep unsafe.Pointer, unlockf func())
func runtime.send(c *hchan, sg *sudog, ep unsafe.Pointer, unlockf pfn)
func runtime.selectnbrecv(t *chantype, elem unsafe.Pointer, c *hchan) (selected bool)
func runtime.selectnbsend(t *chantype, c *hchan, elem unsafe.Pointer) (selected bool)

func runtime.GOMAXPROCS(n int) int

// syscalls
func syscall.init()
func runtime.entersyscall(dummy int32)
func runtime.reentersyscall(pc, sp uintptr/p)
//func Syscall(trap int64, a1, a2, a3 int64) (r1, r2, err int64)
func syscall.Syscall(trap int64, a1 int64=SYSCALL_NO, a2 int64/p, a3 int64) (r1 int64, r2 int64, err int64)
func runtime.exitsyscall(dummy int32)
func runtime.exitsyscallfast() bool
func runtime.exitsyscallfast_pidle() bool
func runtime.asminit()
func runtime.entersyscallblock(dummy int32)
func runtime.entersyscallblock_handoff()
func runtime.entersyscall_sysmon()
func syscall.errnoErr(e Errno=errno) error

func runtime.asmcgocall(fn, arg unsafe.Pointer) int32
func runtime.cgocall(fn, arg unsafe.Pointer) int32
func runtime.endcgo(mp *m)
func runtime.cgoCheckArg(t *_type, p unsafe.Pointer, indir, top bool, msg string)
func runtime.cgoIsGoPointer(p unsafe.Pointer) bool
func runtime.cmalloc(n uintptr) unsafe.Pointer

func runtime.getcallerpc() uintptr/p
func runtime.getcallersp~(argp unsafe.Pointer) uintptr/p

func syscall.read(fd int, p []byte) (n int, err error)
func syscall.Read(fd int, p []byte) (n int, err error)
func syscall.write(fd int, p []byte) (n int, err error)
func syscall.Write(fd int, p []byte) (n int, err error)
func syscall.socket(domain int, typ int, proto int) (fd int, err error)
func syscall.Socket(domain, typ, proto int) (fd int, err error)
func syscall.openat(dirfd int, path string, flags int, mode uint32) (fd int, err error)
func syscall.getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
func syscall.getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
func syscall.getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error)
func syscall.GetsockoptInt(fd, level, opt int) (value int, err error)
func syscall.setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)
func syscall.SetsockoptInt(fd, level, opt int, value int) (err error)
func syscall.bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
func syscall.Bind(fd int, sa Sockaddr) (err error)
func syscall.connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
func syscall.Close(fd int) (err error)
func syscall.Stat(path string, stat *Stat_t) (err error)
func syscall.Getpeername(fd int) (sa Sockaddr, err error)
func syscall.Getenv(key string) (value string, found bool)
func syscall.copyenv()
func syscall.runtime_envs() []string
func syscall.RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func syscall.BytePtrFromString(s string) (*byte, error)
func syscall.ByteSliceFromString(s string) ([]byte, error)

func runtime.exit(code int32)
func runtime.sleep(ms int32) int32
func runtime.usleep(usec uint32)
func runtime.futexsleep(addr *uint32, val uint32, ns int64)
func runtime.futexwakeup(addr *uint32, cnt uint32)
func runtime.notetsleep(n *note, ns int64) bool
func runtime.nanotime() int64
func runtime.unixnanotime() int64
func runtime.timediv(v int64, div int32, rem *int32)
func runtime.timerproc(tb *timersBucket)
func runtime.notetsleep(n *note, ns int64) bool
func runtime.notetsleepg(n *note, ns int64) bool
func runtime.notesleep(n *note)
func runtime.notewakeup(n *note)
func runtime.wakep()
func time.Sleep(d Duration)
func runtime.addtimer(t *timer)
func runtime.deltimer(t *timer) bool
func runtime.cputicks() int64
func runtime.addtimerLocked(t *timer)
func runtime.siftupTimer(i int)
func runtime.siftdownTimer(i int)

// Errors
func errors.New(text string) error

// Networking
func net.socket(domain int, typ int, proto int) (fd int, err error)
// change to *net.TCPConn
func net.newTCPConn(fd *netFD) *TCPConn
func net.sysSocket(family, sotype, proto int) (int, error)
func runtime.epollcreate(size int32) int32
func runtime.epollcreate1(flags int32) int32
func runtime.epollwait(epfd int32, ev *epollevent, nev int32, timeout int32) int32
func runtime.epollctl(epfd, op, fd int32, ev *epollEvent) int
func runtime.netpollinit()
func runtime.netpollready(gpp *guintptr, pd *pollDesc, mode int32)
func runtime.netpoll(block bool) *g
func runtime.netpollinited() bool
func runtime.netpollopen(fd uintptr, pd *pollDesc) int32
func runtime.netpollunblock(pd *pollDesc, mode int32, ioready bool) *g
func net.runtime_pollOpen(fd uintptr) (uintptr, int)
func net.runtime_pollWait(ctx uintptr, mode int) int
func runtime_pollServerInit()
func net.runtime_pollSetDeadline(ctx uintptr, d int64, mode int)
func net.runtime_pollUnblock(ctx uintptr)
func net.runtime_pollClose(ctx uintptr)
func runtime.netpollblockcommit(gp *g, gpp unsafe.Pointer) bool
func runtime.netpollblock(pd *pollDesc, mode int32, waitio bool) bool
func runtime.netpollclose(fd uintptr) int32

func net.IP.IsLoopback() bool
func net.isZeros(p IP) bool
func net.selfConnect(fd *netFD, err error) bool
func net.parseNSSConfFile(file string) *nssConf
func net.dnsReadConfig(filename string) *dnsConfig
func net.systemConf() *conf
func net.LookupPort(network, service string) (port int, err error)
func net.parseIPv4(s string) net.IP
func net.parseIPv6(s string, zoneAllowed bool) (ip net.IP, zone string)
func net.splitHostZone(s string) (host, zone string)
func net.zoneToInt(zone string) int
func net.zoneToString(zone int) string
func net.SplitHostPort(hostport string) (host, port string, err error)
func net.last(s string, b byte) int
func net.ResolveTCPAddr(network string, address string) (*net.TCPAddr, error)
func net.absDomainName(b []byte) string
func net.IP.To4() IP
func net.parseLiteralIP(addr string) string
func net.isDomainName(s string)
//func net.ParseCIDR(s string) (IP, *IPNet, error)
func net.mustCIDR(s string) *IPNet
//func (ip IP) String() string
func net.IP.String() string
func net.appendHex(dst []byte, i uint32) []byte
//func net.ipToSockaddr(family int, ip IP, port int, zone string) (syscall.Sockaddr, error)
func syscall.Connect(fd int, sa Sockaddr) (err error)
func net.setDefaultSockopts(s, family, sotype int, ipv6only bool) error
func net.trimSpace(x []byte) []byte
func net.removeComment(line []byte) []byte
func net.lowerASCIIBytes(x []byte)
func net.bytesEqual(x, y []byte) bool

//func (m IPMask) Size() (ones, bits int
func net.IPMask.Size() (ones, bits int)

func net.dtoi(s string) (n int, i int, ok bool)
func net.itoa(val int) string
func net.uitoa(val uint) string
func net.xtoi(s string) (n int, i int, ok bool)
func net.setNoDelay(fd *netFD, noDelay bool) error
//func net.newTCPConn(fd *netFD) *TCPConn

func net.releaseThread()
func net.maxListenerBacklog() int
func net.convertErr(res int) error

// Time
func time.init()
func time.now() (sec int64, nsec int32, mono int64)

func runtime.readvarint(p []byte) (newp []byte, val uint32)
func runtime.memmove~(to *any, frm *any, length uintptr)
func runtime.typedmemmove(t *rtype, dst, src unsafe.Pointer)

func runtime.lock(l *mutex)
func runtime.unlock(l *mutex)
func runtime.futex(addr unsafe.Pointer, op int32, val uint32, ts, addr2 unsafe.Pointer, val3 uint32) int32
func sync.init()
func sync.runtime_procPin() int
func sync.runtime_procUnpin()
func sync.(m *Mutex) Lock()
func sync.(m *Mutex) Unlock()
func sync.(rw *RWMutex) RLock()
func sync.(rw *RWMutex) RUnlock()

func sync.(p *Pool) pin() *poolLocal
func sync.(p *Pool) pinSlow() *poolLocal
//func sync.runtime_registerPoolCleanup(cleanup func())
func sync.runtime_registerPoolCleanup(cleanup pfn)

//func sync.(o *Once) Do(f func())
func sync.(o *Once) Do(f pfn)

func sync.(rw *RWMutex) RLock()
func sync.(rw *RWMutex) RUnlock()

// Format
func fmt.init()
func fmt.newPrinter() *pp
func fmt.parsenum(s string, start, end int) (num int, isnum bool, newi int)

func runtime.findrunnable() (gp *g, inheritTime bool)
func runtime.runqsteal(_p_, p2 *p, stealRunNextG bool) *g
func runtime.gopreempt_m(gp *g)
func runtime.preemptall() bool
func runtime.goschedImpl(gp *g)
//func runqgrab(_p_ *p, batch *[256]guintptr, batchHead uint32, stealRunNextG bool) uint32
func runtime.runqgrab(_p_ *p, batch *guintptr, batchHead uint32, stealRunNextG bool) uint32
func runtime.runqget(_p_ *p) (gp *g, inheritTime bool)
func runtime.globrunqget(_p_ *p, max int32) *g
func runtime.runqput(_p_ *p, gp *g, next bool)
func runtime.runqempty~(_p_ *p) bool
func runtime.goready(gp *g, traceskip int)
func runtime.deferreturn(arg0 uintptr/p)
func runtime.deferproc(siz int32, fn *funcval)
func runtime.newdefer(siz int32) *_defer
func runtime.freedefer(d *_defer)
//func mcall(fn func(*g))
func runtime.mcall(fn pfn)
func runtime.retake(now int64) uint32
func runtime.startlockedm(gp *g)
func runtime.stoplockedm()
func runtime.sysmon()
func runtime.mspinning()
func runtime.resetspinning()
func runtime.newextram()

func runtime.return0()
func runtime.adjustsudogs(gp *g, adjinfo *adjustinfo)
func runtime.acquireSudog() *sudog
func runtime.releaseSudog(s *sudog)
func runtime.gfput(_p_ *p, gp *g)
func runtime.stackinit()
func runtime.copystack(gp *g, newsize uintptr)
func runtime.stackcacherefill(c *mcache, order uint8)
//func systemstack(fn func())
func runtime.systemstack(fn pfn)
func runtime.stackpoolalloc(order uint8) gclinkptr
func runtime.newstack()
func runtime.morestack()
func runtime.morestack_noctxt()
func runtime.stacklog2(n uintptr) int
func runtime.rewindmorestack(buf *gobuf)
func runtime.sigaltstack(new, old *stackt)
func runtime.signalstack(s *stack)
func runtime.setsigstack(i int32)
func runtime.initsig(preinit bool)
func runtime.malg(stacksize int32) *g
func runtime.injectglist(glist *g)
func runtime.sigInstallGoHandler(sig uint32) bool
func runtime.rt_sigaction(sig uintptr, new, old *sigactiont, size uintptr) int32
func runtime.rtsigprocmask(sig uint32, new, old *sigset, size int32)
func runtime.msigsave(mp *m)

func runtime.checkdead()
func runtime.schedule()
func runtime.sched_getaffinity(pid, len uintptr, buf *uintptr) int32
func runtime.mput(mp *m)
func runtime.stopm()
func runtime.releasep() *p
func runtime.pidleput(_p_ *p)
func runtime.pidleget() *p
func runtime.readgstatus(gp *g) uint32
func runtime.allgadd(gp *g)
func runtime.mpreinit(mp *m)
func runtime.publicationBarrier()
func runtime.writebarrierptr_nostore(dst *uintptr, src uintptr/p)
func runtime.gcMaxStackBarriers(stackSize int) (n int)
func runtime.gcLockStackBarriers(gp *g)
func runtime.gcUnlockStackBarriers(gp *g)
func runtime.readgogc() int32
func runtime.deductSweepCredit(spanBytes uintptr, callerSweepPages uintptr)
func runtime.lockextra(nilokay bool) *m
func runtime.unlockextra(mp *m)
func runtime.checkmcount()

// Finalizers
func runtime.findObject(v unsafe.Pointer) (s *mspan, x unsafe.Pointer, n uintptr)
func runtime.createfing()
func runtime.addfinalizer(p unsafe.Pointer, f *funcval, nret uintptr, fint *_type, ot *ptrtype) bool
func runtime.runfinq()

func runtime.newproc1(fn *funcval, argp *uint8, narg int32, nret int32, callerpc uintptr) *g
func runtime.execute(gp *g, inheritTime bool)
func runtime.procyield(cycles uint32)
func runtime.osyield()
func runtime.ready(gp *g, traceskip int, next bool)
//func gopark(unlockf func(*g, unsafe.Pointer) bool, lock unsafe.Pointer, reason string, traceEv byte, traceskip int)
func runtime.gopark(unlockf pfn, lock unsafe.Pointer, reason string, traceEv byte, traceskip int)
func runtime.park_m(gp *g)
func runtime.goparkunlock(lock *mutex, reason string, traceEv byte, traceskip int)
func runtime.parkunlock_c(gp *g, lock unsafe.Pointer) bool
func threadentry(v uintptr/p)
func runtime.unlockOSThread()
func runtime.adjustframe(frame *stkframe, arg unsafe.Pointer) bool
func runtime.adjuststkbar(gp *g, adjinfo *adjustinfo)
func runtime.jmpdefer(fv *funcval, argp uintptr)
func runtime.gostartcallfn(gobuf *gobuf, fv *funcval)

func runtime.gettid() uint32

func runtime.mstart()
func runtime.mstart1()

func runtime.fastrand1~() uint32
func runtime.getRandomData(r []byte)

func runtime.moduledataverify()
func runtime.moduledataverify1(datap *moduledata)
func runtime.testdefersizes()
func runtime.findfunc(pc uintptr) funcInfo
func runtime.findmoduledatap(pc uintptr/p) *moduledata
func runtime.funcspdelta(f *_func, targetpc uintptr/p, cache *pcvalueCache) int32
func runtime.pcvalue(f *_func, off int32, targetpc uintptr/p, cache *pcvalueCache, strict bool) int32
func runtime.pcdatavalue(f *_func, table int32, targetpc uintptr/p, cache *pcvalueCache) int32
func runtime.funcdata(f *_func, i int32) unsafe.Pointer
func runtime.funcname(f *_func) string
func runtime.cfuncname(f *_func) *byte
func runtime.funcline1(f *_func, targetpc uintptr/p, strict bool) (file string, line int32)
func runtime.funcline(f *_func, targetpc uintptr/p) (file string, line int32)
func runtime.adjustpointers(scanp unsafe.Pointer, cbv *bitvector, adjinfo *adjustinfo, f *_func)
func runtime.step(p []byte, pc *uintptr, val *int32, first bool) (newp []byte, ok bool)
func runtime.getArgInfo(frame *stkframe, f *_func, needArgMap bool) (arglen uintptr, argmap *bitvector)
func runtime.stackmapdata(stkmap *stackmap, n int32) bitvector
func runtime.gotraceback() (level int32, all, crash bool)
func runtime.gentraceback(pc0, sp0, lr0 uintptr/p, gp *g, skip int, pcbuf *uintptr, max int, callback pfn, v unsafe.Pointer, flags uint) int
func runtime.showframe(f *_func, gp *g) bool
func runtime.goroutineheader(gp *g)
func runtime.printcreatedby(gp *g)
func runtime.tracebackothers(me *g)
//func tracebackdefers(gp *g, callback func(*stkframe, unsafe.Pointer) bool, v unsafe.Pointer)
func runtime.tracebackdefers(gp *g, callback fn, v unsafe.Pointer)
func runtime.adjustdefers(gp *g, adjinfo *adjustinfo)

func runtime.adjustpointer(adjinfo *adjustinfo, vpp unsafe.Pointer)
func runtime.handoffp(_p_ *p)
func runtime.incidlelocked(v int32)
//func newm(fn func(), _p_ *p)
func runtime.newm(fn pfn, _p_ *p)
func runtime.acquirep(_p_ *p)
func runtime.acquirep1(_p_ *p)
func runtime.gosave(buf *gobuf)
func runtime.gogo(buf *gobuf)
func runtime.prefetchnta~(addr uintptr/p)
func runtime.prefetcht0(addr uintptr/p)
func runtime.prefetcht1(addr uintptr/p)
func runtime.prefetcht2(addr uintptr/p)
func runtime.gfget(_p_ *p) *g
func runtime.newproc(siz int32, fn *funcval)

// Slices
func runtime.makeslice(et *_type, len, cap int) slice
func runtime.growslice(t *slicetype, old slice, cap int) slice

func runtime\internal\atomic.Load~(ptr *uint32) uint32
func runtime\internal\atomic.Load64~(ptr *uint64) uint64
func runtime\internal\atomic.Store64(ptr *uint64, val uint64)
func runtime\internal\atomic.Storeuintptr(ptr *uintptr, new uintptr)
func runtime\internal\atomic.Xchg~(ptr *uint32, new uint32) uint32
func runtime\internal\atomic.Xchg64~(ptr *uint64, new uint64) uint64
func runtime\internal\atomic.Loaduintptr(ptr *uint32, new uint32) uint32
func runtime\internal\atomic.Cas~(ptr *uint32, old, new uint32) bool
func runtime\internal\atomic.Casp1~(ptr *unsafe.Pointer, old, new unsafe.Pointer) bool
func runtime\internal\atomic.Cas64~(ptr *uint64, old, new uint64) bool
func runtime\internal\atomic.Casuintptr(ptr *uintptr, old, new uintptr) bool
func runtime\internal\atomic.Storep1(ptr unsafe.Pointer/p, val unsafe.Pointer/p)$a
func runtime\internal\atomic.Loadp(ptr unsafe.Pointer) unsafe.Pointer

func runtime.mapassign1(t *maptype, h *hmap, key unsafe.Pointer, val unsafe.Pointer)
func runtime.mapaccess2_fast64(t *maptype, h *hmap, key uint64) (unsafe.Pointer, bool)
func runtime.mapaccess1_faststr(t *maptype, h *hmap, ky string) unsafe.Pointer
func runtime.mapaccess2_faststr(t *maptype, h *hmap, ky string) (unsafe.Pointer, bool)
func runtime.mapaccess1_fast32(t *maptype, h *hmap, key uint32) unsafe.Pointer
func runtime.makemap(t *maptype, hint int64, h *hmap, bucket unsafe.Pointer) *hmap
func runtime.mapzero(t *_type)
func runtime.hashGrow(t *maptype, h *hmap)
func runtime.growWork(t *maptype, h *hmap, bucket uintptr)
func runtime.mapdelete(t *maptype, h *hmap, key unsafe.Pointer)

func runtime.aeshash(p unsafe.Pointer, h, s uintptr) uintptr/x
func runtime.aeshashstr(p unsafe.Pointer, h uintptr) uintptr/x
func runtime.aeshash32(p unsafe.Pointer, h uintptr) uintptr/x
func runtime.aeshash64(p unsafe.Pointer, h uintptr) uintptr/x
func runtime.evacuate(t *maptype, h *hmap, oldbucket uintptr)

// Strings
func runtime.atoi(s string) int
func strings.IndexByte(s string, c byte) int
func runtime.findnull~(s *byte) int/p
func runtime.gostring(p *byte) string
func runtime.gostringnocopy(str *byte) string
func runtime.rawstring(size int) (s string, b []byte)
func runtime.rawstringtmp(buf *tmpBuf, l int) (s string, b []byte)
func runtime.rawmem(size uintptr) unsafe.Pointer
func runtime.slicebytetostring(buf *tmpBuf, b []byte) (str string)
func runtime.concatstrings(buf *tmpBuf, a []string) string
func runtime.eqstring(string, string) bool
func runtime.cmpstring(s1, s2 string) int

// Bytes
func bytes.IndexByte(s []byte, c byte) int

// Strconv
//func runtime.formatDigits(dst []byte, shortest bool, neg bool, digs decimalSlice, prec int, fmt byte) []byte
func runtime.adjustLastDigit(d *decimalSlice, currentDiff, targetDiff, maxDiff, ulpDecimal, ulpBinary uint64) bool

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
func os.fillFileStatFromSys(fs *fileStat, name string)

// OS
func os.init()
func os.basename(name string) string
func os.epipecheck(file *File, e error)
func os.IsNotExist(err error) bool
func os.isNotExist(err error) bool

func runtime.mSysStatInc(sysStat *uint64, n uintptr)

// UTF8
func unicode\utf8.DecodeRuneInString(s string) (r rune, size int)

// Sorting
// func (r reverse) Less(i, j int) bool
func sort.reverse.Less(i, j int) bool


#if GOVERSION >= 1.9
	func runtime.recordForPanic(b []byte)
	func runtime.nextFreeFast(s *mspan) gclinkptr
	func runtime.additab(m *itab, locked, canfail bool)
	func runtime.mapassign_faststr(t *maptype, h *hmap, ky string) unsafe.Pointer
	func runtime.mapdelete_faststr(t *maptype, h *hmap, ky string)
	func runtime.convT2E16(t *_type, elem unsafe.Pointer) (e eface)
	func runtime.convT2E64(t *_type, elem unsafe.Pointer) (e eface)
	func runtime.convT2I64(tab *itab, elem unsafe.Pointer) (i iface)
	func runtime.exitsyscallfast_reacquired()
	func runtime.convT2Estring(t *_type, elem unsafe.Pointer) (e eface)
	func runtime.writebarrierptr_prewrite(dst *uintptr, src uintptr)
	func runtime.writebarrierptr_prewrite1(dst *uintptr, src uintptr)
#endif
