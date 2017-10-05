// This is obviously not really golang code;
// there is still work to do with porting the C grammar over.

func abc.bcd(int16 hi);

func runtime.gcenable();
func runtime.osinit();

//func convT2E(t *_type, elem unsafe.Pointer) (e eface)
func runtime.convT2E(void *t, void *elem);
//func assertE2T2(typ *byte, iface any) (ret any, ok bool)
func runtime.assertE2T2(byte *typ, void *iface);
//func assertI2T2(typ *byte, iface any) (ret any, ok bool)
func runtime.assertI2T2(byte *typ, void *iface);
//func efacethash(i1 any) (ret uint32)
uint32 runtime.efacethash/x(void *i1);
//func memhash(p unsafe.Pointer, seed, s uintptr) uintptr
uintptr runtime.memhash(void *p, uintptr seed, uintptr s);
//func getitab(inter *interfacetype, typ *_type, canfail bool) *itab {
void *runtime.getitab(void *inter, void *typ, bool canfail);


// value

//func typedmemmove(t *rtype, dst, src unsafe.Pointer)
func runtime.typedmemmove(void *t, void *dst, void *src);

// malloc/dynamic memory

func runtime.mallocinit();
//func mallocgc(size uintptr, typ *_type, needzero bool) unsafe.Pointer
void *runtime.mallocgc(uintptr size, void *typ, bool needzero);
//func newobject(typ *_type) unsafe.Pointer 
void *runtime.newobject(void *typ);
//func newobject(typ *_type) unsafe.Pointer
void *runtime.newobject(void *typ);
//func newarray(typ *_type, n int) unsafe.Pointer
void *runtime.newarray(void *type, int n);
//func persistentalloc(size, align uintptr, sysStat *uint64) unsafe.Pointer {
void *runtime.persistentalloc(uintptr size, uintptr align, void *sysStat);
//func persistentalloc1(size, align uintptr, sysStat *uint64) unsafe.Pointer {
void *runtime.persistentalloc1(uintptr size, uintptr align, void *sysStat);
//func nextSample() int32
int32 runtime.nextSample();

//func (h heapBits) initSpan(s *mspan)
func runtime.heapBits.initSpan(void *s);
//func progToPointerMask(prog *byte, size uintptr) bitvector
void runtime.progToPointerMask(byte *prog, uintptr size);
//func runGCProg(prog, trailer, dst *byte, size int) uintptr
uintptr runtime.runGCProg(byte *prog, byte *trailer, byte *dst, int size);


//func (h *mheap) sysAlloc(n uintptr) unsafe.Pointer
void *runtime.sysAlloc(uintptr *n);

//func getsig(i uint32) uintptr
uintptr runtime.getsig(uint32 i);
//func setsig(i uint32, fn uintptr)
void *runtime.setsig(uint32 i, pfn fn);

//func gogetenv(key string) string
string runtime.gogetenv(string key);
//func GOROOT() string
string runtime.GOROOT();

// Should be unsafe.Pointer for both params
int runtime.strequal(void *p, void *q);

//func atomicstorep(ptr unsafe.Pointer, new unsafe.Pointer
func runtime.atomicstorep(void *ptr, void *new);

//func StorePointer(addr *unsafe.Pointer, val unsafe.Pointer)
//void sync/atomic.StorePointer(void **addr, void *val);

//func casp(ptr *unsafe.Pointer, old, new unsafe.Pointer) bool
bool runtime.casp(void *ptr, void *old, void *new);

// func mmap(addr unsafe.Pointer, n uintptr, prot, flags, fd int32, off uint32) unsafe.Pointer
void *runtime.mmap(void *addr, uintptr n, uint prot/x, uint flags/x, int fd, uint32 off);

// channels
//func closechan(c *hchan)
func runtime.closechan(void *c);
//func makechan(t *chantype, size int) *hchan
void *runtime.makechan(void *t, int size);

//func GOMAXPROCS(n int) int
int runtime.GOMAXPROCS(int n);

// syscalls
func runtime.entersyscall(int32 dummy);
//func Syscall(trap int64, a1, a2, a3 int64) (r1, r2, err int64);
//func exitsyscall(dummy int32) {
func runtime.exitsyscall(int32 dummy);
//func exitsyscallfast() bool {
bool runtime.exitsyscallfast();

void *syscall.Syscall(int64 trap, int64 a1, int64 a2, int64 a3);
//func getcallerpc() uintptr
uintptr runtime.getcallerpc/p();
//func getcallersp(argp unsafe.Pointer) uintptr
uintptr runtime.getcallersp/p(void *argp);

//func Write(fd int, p []byte) (n int, err error)
int syscall.Write(int fd, void *p);

//func exit(code int32)
func runtime.exit(int32 code);
//func sleep(ms int32) int32
int32 runtime.sleep(int32 ms);
//func usleep(usec uint32)
func runtime.usleep(uint32 usec);
//func futexsleep(addr *uint32, val uint32, ns int64)
func runtime.futexsleep(uint32 *addr, uint32 val, int64 ns);

// Errors
//func New(text string) error
void *errors.New(string text);




int main.Somefunc(int hi/x);
func main.Somefunc2(int hi/x, int hi2/x);
int main.Somefunc3/x(string hi);
int main.Somefunc4/x(string hi, string hi2);
func main.Somefunc5(bool hi1, int hi2);
func main.Somefunc6(int signed1, uint signed2);
func main.Somefunc7(uint i1/x, uint i2/x, uint i3/x, uint i4/x);
