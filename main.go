//go:build linux && amd64

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	blockSize = 4096
	limeMagic = 0x4c694d45
)

type memRange struct {
	Start uint64
	End   uint64
}

type request struct {
	Phys uint64
	Seq  uint64
	Size uint32
	Pad  uint32
}

type result struct {
	Seq    uint64
	Status int32
	Size   uint32
	Data   [blockSize]byte
}

type limeHeader struct {
	Magic    uint32
	Version  uint32
	Start    uint64
	End      uint64
	Reserved [8]byte
}

func parseIOMem(path string) ([]memRange, uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	var ranges []memRange
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		left, right, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(right) != "System RAM" {
			continue
		}

		a, b, ok := strings.Cut(strings.TrimSpace(left), "-")
		if !ok {
			return nil, 0, fmt.Errorf("invalid iomem line: %q", sc.Text())
		}

		start, e1 := strconv.ParseUint(strings.TrimSpace(a), 16, 64)
		end, e2 := strconv.ParseUint(strings.TrimSpace(b), 16, 64)
		if e1 != nil || e2 != nil || end < start {
			return nil, 0, fmt.Errorf("invalid RAM range: %q", sc.Text())
		}

		if start == 0 && end == 0 {
			return nil, 0, errors.New(
				"iomem addresses appear hidden: System RAM is 0-0",
			)
		}
		if end == math.MaxUint64 {
			return nil, 0, errors.New("unsupported RAM range ending at UINT64_MAX")
		}

		ranges = append(ranges, memRange{Start: start, End: end})
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	if len(ranges) == 0 {
		return nil, 0, errors.New("no System RAM ranges found")
	}

	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].Start < ranges[j].Start
	})

	var total uint64
	for i, r := range ranges {
		if i > 0 && r.Start <= ranges[i-1].End {
			return nil, 0, fmt.Errorf(
				"overlapping System RAM ranges near %#x", r.Start,
			)
		}

		size := r.End - r.Start + 1
		if size > math.MaxUint64-total {
			return nil, 0, errors.New("total RAM size overflow")
		}
		total += size
	}

	return ranges, total, nil
}

func symbolAddress(path, name string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[2] != name {
			continue
		}

		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			return 0, err
		}
		if addr == 0 {
			return 0, fmt.Errorf("%s address is hidden or zero", name)
		}
		return addr, nil
	}

	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("symbol %q not found", name)
}

type collector struct {
	coll *ebpf.Collection
	hook link.Link
	req  *ebpf.Map
	res  *ebpf.Map
	seq  uint64
}

func newCollector(object string, symbol uint64) (*collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		return nil, fmt.Errorf("read BPF object: %w", err)
	}

	constants := map[string]interface{}{
		"page_offset_symbol": symbol,
		"collector_tgid":     uint32(os.Getpid()),
	}

	for name, value := range constants {
		variable, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf(
				"BPF variable %q not found: rebuild the BPF object with -g",
				name,
			)
		}

		if err := variable.Set(value); err != nil {
			return nil, fmt.Errorf("set BPF variable %q: %w", name, err)
		}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection: %w", err)
	}

	prog := coll.Programs["dump_page"]
	req := coll.Maps["requests"]
	res := coll.Maps["results"]
	if prog == nil || req == nil || res == nil {
		coll.Close()
		return nil, errors.New("BPF object lacks expected program or maps")
	}

	hook, err := link.Tracepoint(
		"syscalls", "sys_enter_getpid", prog, nil,
	)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	return &collector{
		coll: coll,
		hook: hook,
		req:  req,
		res:  res,
	}, nil
}

func (c *collector) Close() {
	_ = c.hook.Close()
	c.coll.Close()
}

// Read must be called serially: this backend has one request/result slot.
func (c *collector) Read(phys uint64, size uint32) ([]byte, error) {
	if size == 0 || size > blockSize {
		return nil, errors.New("invalid read size")
	}
	if c.seq == math.MaxUint64 {
		return nil, errors.New("request sequence overflow")
	}
	c.seq++

	key := uint32(0)
	req := request{
		Phys: phys,
		Seq:  c.seq,
		Size: size,
	}
	if err := c.req.Update(&key, &req, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("update request: %w", err)
	}

	// Real syscall: do not substitute a userspace/cached getpid wrapper.
	_, _, errno := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("getpid trigger: %w", errno)
	}

	var res result
	if err := c.res.Lookup(&key, &res); err != nil {
		return nil, fmt.Errorf("lookup result: %w", err)
	}

	if res.Seq != req.Seq {
		return nil, fmt.Errorf(
			"BPF request not completed: got sequence %d, want %d",
			res.Seq, req.Seq,
		)
	}
	if res.Status != 0 {
		return nil, fmt.Errorf(
			"physical read at %#x: BPF status %d",
			phys, res.Status,
		)
	}
	if res.Size != size {
		return nil, fmt.Errorf(
			"unexpected result size: got %d, want %d", res.Size, size,
		)
	}

	return res.Data[:int(size)], nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func run() (retErr error) {
	outPath := flag.String("out", "", "output LiME file")
	object := flag.String("bpf", "bpf/phys_dump.bpf.o", "BPF object")
	flag.Parse()

	if *outPath == "" {
		return errors.New("usage: sudo ./physdump -out /mnt/evidence/ram.lime")
	}
	if os.Geteuid() != 0 {
		return errors.New("run as root; kernel security policy may still deny access")
	}

	ctx, stop := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM,
	)
	defer stop()

	ranges, total, err := parseIOMem("/proc/iomem")
	if err != nil {
		return fmt.Errorf("iomem: %w", err)
	}

	symbol, err := symbolAddress("/proc/kallsyms", "page_offset_base")
	if err != nil {
		return fmt.Errorf("kallsyms: %w", err)
	}

	c, err := newCollector(*object, symbol)
	if err != nil {
		return err
	}
	defer c.Close()

	// Fail before creating output if the read mechanism does not work.
	firstSize := uint64(blockSize)
	if n := ranges[0].End - ranges[0].Start + 1; n < firstSize {
		firstSize = n
	}
	if _, err := c.Read(ranges[0].Start, uint32(firstSize)); err != nil {
		return fmt.Errorf("preflight read: %w", err)
	}

	if _, err := os.Lstat(*outPath); err == nil {
		return fmt.Errorf("output already exists: %s", *outPath)
	} else if !os.IsNotExist(err) {
		return err
	}

	partial := *outPath + ".partial"
	out, err := os.OpenFile(
		partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600,
	)
	if err != nil {
		return err
	}

	closed := false
	defer func() {
		if !closed {
			if err := out.Close(); retErr == nil && err != nil {
				retErr = err
			}
		}
		if retErr != nil {
			fmt.Fprintf(os.Stderr, "Incomplete output, if created: %s\n", partial)
		}
	}()

	fmt.Printf(
		"System RAM: %d ranges, %d bytes\npage_offset_base symbol: %#x\n",
		len(ranges), total, symbol,
	)

	var done uint64
	for _, r := range ranges {
		fmt.Printf("Reading %#x-%#x\n", r.Start, r.End)

		h := limeHeader{
			Magic:   limeMagic,
			Version: 1,
			Start:   r.Start,
			End:     r.End,
		}
		if err := binary.Write(out, binary.LittleEndian, &h); err != nil {
			return err
		}

		for phys := r.Start; phys <= r.End; {
			if err := ctx.Err(); err != nil {
				return err
			}

			n := uint64(blockSize)
			if remaining := r.End - phys + 1; remaining < n {
				n = remaining
			}

			data, err := c.Read(phys, uint32(n))
			if err != nil {
				return err
			}
			if err := writeAll(out, data); err != nil {
				return err
			}

			phys += n
			done += n
		}
	}

	if err := out.Sync(); err != nil {
		return err
	}
	err = out.Close()
	closed = true
	if err != nil {
		return err
	}

	// Do not overwrite a destination created concurrently.
	// Linux/filesystem support for RENAME_NOREPLACE is required.
	if err := unix.Renameat2(
		unix.AT_FDCWD, partial,
		unix.AT_FDCWD, *outPath,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}

	fmt.Printf("Completed: %s; acquired %d bytes\n", *outPath, done)
	return nil
}

func main() {
	if err := run(); err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			fmt.Fprintf(os.Stderr, "Verifier:\n%+v\n", verifierErr)
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
