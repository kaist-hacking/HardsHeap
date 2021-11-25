#!/usr/bin/env python
import os
import sys
import signal
import tempfile

from pwn import *

# TODO: Support both 32-bit and 64-bit
SIZEOF_PTR = 8

FUZZ_ALLOCATE = 0
FUZZ_DEALLOCATE = 1
FUZZ_VULN = 2
FUZZ_FILL_HEAP = 4
FUZZ_FILL_BUFFER = 3

VULN_OVERFLOW = 0
VULN_OFF_BY_ONE_NULL = 1
VULN_OFF_BY_ONE = 2
VULN_WRITE_AFTER_FREE = 3
VULN_DOUBLE_FREE = 4
VULN_ARBITRARY_FREE = 5

FUZZ_INT = 0
FUZZ_PTR = 1

# FUZZ_INT
INTERESTING_VALUE = 0
BUFFER_HEAP_OFFSET = 1
UNALIGNED_SIZE = 4

# FUZZ_PTR
NULL = 0
HEAP_ADDRESS = 1
BUFFER_ADDRESS = 2
CONTAINER_ADDRESS = 3

def get_unaligned_type_and_beg(sz):
    TYPE_MAP = [0, 2, 4, 5]

    for i in xrange(5):
        beg = 1 << (5 * i)
        end = 1 << (5 * (i + 1))
        if sz >= beg and sz < end:
            break
    return beg, TYPE_MAP[i]

def encode_offset(off):
    assert(off >= -4 and off <= 4)
    return p8(off + 4)

class DataGenerator(object):
    def __init__(self):
        self.data = ""

    def add(self, kind, args):
        raise

class TestGenerator(object):
    def __init__(self, name):
        self.name = "driver_test_%s" % name
        self.data = ""
        self.gid = 0
        if len(sys.argv) > 1:
            self.should_dump = bool(int(sys.argv[1]))
        else:
            self.should_dump = False

    def allocate(self, *args):
        self.data += p8(FUZZ_ALLOCATE)
        self._fuzz_int(*args)

        hid = self.gid
        self.gid += 1
        return hid

    def deallocate(self, index):
        self.data += p8(FUZZ_DEALLOCATE) + p16(index)

    def fill_buffer(self, index, args):
        self.data += p8(FUZZ_FILL_BUFFER) + p16(index) + p8(len(args) - 1)
        self._generate_value(args)

    def fill_heap(self, index, head, args):
        self.data += p8(FUZZ_FILL_HEAP) + p16(index) + p8(head) + p8(len(args) - 1)
        self._generate_value(args)

    def overflow(self, index, args):
        self._fuzz_vuln(VULN_OVERFLOW)
        self.data += p16(index) + p8(len(args) - 1)
        self._generate_value(args)

    def double_free(self, index):
        self._fuzz_vuln(VULN_DOUBLE_FREE)
        self.data += p16(index)

    def arbitrary_free(self, index):
        self._fuzz_vuln(VULN_ARBITRARY_FREE)
        self.data += p16(index)

    def write_after_free(self, index, overflow, args):
        self._fuzz_vuln(VULN_WRITE_AFTER_FREE)
        self.data += p16(index) + p8(overflow) + p8(len(args) - 1)
        self._generate_value(args)

    def off_by_one_null(self, index):
        self._fuzz_vuln(VULN_OFF_BY_ONE_NULL)
        self.data += p16(index)

    def dump_to_file(self):
        if not os.path.exists("testcases"):
            os.makedirs("testcases")
        with open(os.path.join("testcases", self.name), "wb") as f:
            f.write(self.data)
        return True

    def run(self):
        devnull = open(os.devnull, "wb")
        tmp = tempfile.NamedTemporaryFile(delete=False).name
        with open(tmp, "wb") as f:
            f.write(self.data)

        driver = os.path.abspath(os.path.join(os.path.dirname(__file__), "driver"))
        p = subprocess.Popen([driver, tmp], stdin=subprocess.PIPE,
                stdout=devnull,
                stderr=devnull)
        p.communicate()
        retcode = p.wait()
        if retcode != -signal.SIGUSR2:
            print("FAILED: %s (retcode: %d)" % (self.name, retcode))
        os.remove(tmp)

    def finalize(self):
        if self.should_dump:
            return self.dump_to_file()
        else:
            return self.run()

    def _generate_value(self, args):
        for arg in args:
            kind = arg[0]
            farg = arg[1:]
            self.data += p8(kind)

            if kind == FUZZ_INT:
                self._fuzz_int(*farg)
            elif kind == FUZZ_PTR:
                self._fuzz_ptr(*farg)
            else:
                raise ValueError("Kind should be either FUZZ_INT or FUZZ_PTR")

    def _fuzz_unaligned_size(self, sz):
        beg, ty = get_unaligned_type_and_beg(sz)
        self.data += p8(ty)
        self.data += p32(sz - beg)

    def _fuzz_int_interesting_value(self, val):
        interesting_values = [
          -1,
          -SIZEOF_PTR,
          0,
          SIZEOF_PTR
        ]

        idx = interesting_values.index(val)
        assert(idx >= 0)
        self.data += p8(idx)

    def _fuzz_int_buffer_heap_offset(self, *args):
        assert(len(args) == 4)
        self.data += (p16(args[0]) + p16(args[1]) + p8(args[2])
                + encode_offset(args[3] / SIZEOF_PTR))

    def _fuzz_int(self, *args):
        kind = args[0]
        self.data += p8(kind)
        if kind == UNALIGNED_SIZE:
            self._fuzz_unaligned_size(*args[1:])
        elif kind == BUFFER_HEAP_OFFSET:
            self._fuzz_int_buffer_heap_offset(*args[1:])
        elif kind == INTERESTING_VALUE:
            self._fuzz_int_interesting_value(*args[1:])
        else:
            raise ValueError("No such kind in _fuzz_int(): %d" % kind)

    def _fuzz_ptr(self, *args):
        kind = args[0]
        self.data += p8(kind)

        if kind == NULL:
            return
        elif kind == BUFFER_ADDRESS:
            self._fuzz_ptr_buffer_address(*args[1:])
        elif kind == HEAP_ADDRESS:
            self._fuzz_ptr_heap_address(*args[1:])
        elif kind == CONTAINER_ADDRESS:
            self._fuzz_ptr_container_address(*args[1:])
        else:
            raise ValueError("No such kind in _fuzz_ptr(): %d" % kind)

    def _fuzz_ptr_buffer_address(self, *args):
        assert(len(args) == 1)
        self.data += p16(args[0])

    def _fuzz_ptr_container_address(self, *args):
        assert(len(args) == 2)
        self.data += p16(args[0])
        assert(args[1] % SIZEOF_PTR == 0)
        self.data += encode_offset(args[1] / SIZEOF_PTR)

    def _fuzz_ptr_heap_address(self, *args):
        assert(len(args) == 2)
        self.data += p16(args[0])
        assert(args[1] % SIZEOF_PTR == 0)
        self.data += encode_offset(args[1] / SIZEOF_PTR)

    def _fuzz_vuln(self, kind):
        self.data += p8(FUZZ_VULN) + p8(kind)

def test_fastbin_dup():
    tg = TestGenerator("fastbin_dup")
    h1 = tg.allocate(UNALIGNED_SIZE, 8)
    h2 = tg.allocate(UNALIGNED_SIZE, 8)
    tg.deallocate(h1)
    tg.deallocate(h2)
    tg.double_free(h1)
    for i in xrange(3):
        tg.allocate(UNALIGNED_SIZE, 8)
    tg.finalize()

def test_fastbin_dup_into_stack():
    tg = TestGenerator("fastbin_dup_into_stack")
    h1 = tg.allocate(UNALIGNED_SIZE, 8)
    h2 = tg.allocate(UNALIGNED_SIZE, 8)
    h3 = tg.allocate(UNALIGNED_SIZE, 8)
    tg.deallocate(h1)
    tg.deallocate(h3)
    tg.double_free(h1)
    h4 = tg.allocate(UNALIGNED_SIZE, 8)
    h5 = tg.allocate(UNALIGNED_SIZE, 8)

    tg.fill_buffer(1, [(FUZZ_INT, UNALIGNED_SIZE, 0x20)])
    tg.fill_heap(h4, True, [(FUZZ_PTR, BUFFER_ADDRESS, 0)])
    tg.allocate(UNALIGNED_SIZE, 8)
    tg.allocate(UNALIGNED_SIZE, 8)

    tg.finalize()

def test_unsafe_unlink():
    tg = TestGenerator("unsafe_unlink")
    h1 = tg.allocate(UNALIGNED_SIZE, 0x80)
    h2 = tg.allocate(UNALIGNED_SIZE, 0x80)
    tg.fill_heap(h1, True, [
        (FUZZ_PTR, NULL),
        (FUZZ_INT, UNALIGNED_SIZE, 8),
        (FUZZ_PTR, CONTAINER_ADDRESS, h1, SIZEOF_PTR * -3),
        (FUZZ_PTR, CONTAINER_ADDRESS, h1, SIZEOF_PTR * -2)])

    tg.overflow(h1, [
        (FUZZ_INT, UNALIGNED_SIZE, 0x80),
        (FUZZ_INT, UNALIGNED_SIZE, 0x90)])

    tg.deallocate(h2)
    tg.fill_heap(h1, True, [
       (FUZZ_PTR, NULL),
       (FUZZ_PTR, NULL),
       (FUZZ_PTR, NULL),
       (FUZZ_PTR, BUFFER_ADDRESS, 0)
    ])
    tg.fill_heap(h1, True, [
        (FUZZ_INT, UNALIGNED_SIZE, 0x4142)
    ])
    tg.finalize()

def test_house_of_spirit():
    tg = TestGenerator("house_of_spirit")
    h1 = tg.allocate(UNALIGNED_SIZE, 0x80)
    tg.fill_buffer(0, [
        (FUZZ_PTR, NULL),
        (FUZZ_INT, UNALIGNED_SIZE, 0x40)])
    tg.fill_buffer(9,
        [(FUZZ_INT, UNALIGNED_SIZE, 0x1234)])
    tg.arbitrary_free(2)
    tg.allocate(UNALIGNED_SIZE, 0x30)
    tg.finalize()

def test_poison_null_byte():
    tg = TestGenerator("poison_null_byte")
    h1 = tg.allocate(UNALIGNED_SIZE, 0x100)
    h2 = tg.allocate(UNALIGNED_SIZE, 0x200)
    h3 = tg.allocate(UNALIGNED_SIZE, 0x100)
    tg.fill_heap(h2, False,[
        (FUZZ_INT, UNALIGNED_SIZE, 0x200),
        (FUZZ_PTR, NULL),
        (FUZZ_PTR, NULL)
        ])
    tg.deallocate(h2)
    tg.off_by_one_null(h1)
    h4 = tg.allocate(UNALIGNED_SIZE, 0x100)
    h5 = tg.allocate(UNALIGNED_SIZE, 0x80)
    tg.deallocate(h4)
    tg.deallocate(h3)
    tg.allocate(UNALIGNED_SIZE, 0x300)
    tg.finalize()

def test_house_of_lore():
    tg = TestGenerator("house_of_lore")
    h1 = tg.allocate(UNALIGNED_SIZE, 128)
    tg.fill_buffer(0,[
        (FUZZ_PTR, NULL),
        (FUZZ_PTR, NULL),
        (FUZZ_PTR, HEAP_ADDRESS, h1, -2 * SIZEOF_PTR),
        (FUZZ_PTR, BUFFER_ADDRESS, 4)])
    tg.fill_buffer(6, [(FUZZ_PTR, BUFFER_ADDRESS, 0)])
    h2 = tg.allocate(UNALIGNED_SIZE, 1000)
    tg.deallocate(h1)
    h3 = tg.allocate(UNALIGNED_SIZE, 1200)
    tg.write_after_free(h1, True, [
        (FUZZ_PTR, NULL),
        (FUZZ_PTR, BUFFER_ADDRESS, 0)])
    h4 = tg.allocate(UNALIGNED_SIZE, 128)
    h5 = tg.allocate(UNALIGNED_SIZE, 128)
    tg.finalize()

def test_overlapping_chunks():
    tg = TestGenerator("overlapping_chunks")
    h1 = tg.allocate(UNALIGNED_SIZE, 0xf8)
    h2 = tg.allocate(UNALIGNED_SIZE, 0xf8)
    h3 = tg.allocate(UNALIGNED_SIZE, 0x78)
    tg.deallocate(h2)
    tg.overflow(h1, [
        (FUZZ_PTR, NULL),
        (FUZZ_INT, UNALIGNED_SIZE, 0x101 + 0x40)
    ])
    tg.allocate(UNALIGNED_SIZE, 0xf9 + 0x30)
    tg.finalize()

def test_overlapping_chunks_2():
    tg = TestGenerator("overlapping_chunks_2")
    h1 = tg.allocate(UNALIGNED_SIZE, 0x108)
    h2 = tg.allocate(UNALIGNED_SIZE, 0x108)
    h3 = tg.allocate(UNALIGNED_SIZE, 0x108)
    h4 = tg.allocate(UNALIGNED_SIZE, 0x108)
    h5 = tg.allocate(UNALIGNED_SIZE, 0x108)
    tg.deallocate(h4)
    tg.overflow(h1, [
        (FUZZ_PTR, NULL),
        (FUZZ_INT, UNALIGNED_SIZE, 0x111 + 0x110)
    ])
    tg.deallocate(h2)
    tg.allocate(UNALIGNED_SIZE, 0x150)
    tg.finalize()

def test_house_of_force():
    tg = TestGenerator("house_of_force")
    h1 = tg.allocate(UNALIGNED_SIZE, 0x108)
    tg.overflow(h1, [
        (FUZZ_PTR, NULL),
        (FUZZ_INT, INTERESTING_VALUE, -1)
    ])
    tg.allocate(BUFFER_HEAP_OFFSET, 0, 0, False, 0)
    tg.allocate(UNALIGNED_SIZE, 0x100)
    tg.finalize()

def test_unsorted_bin_attack():
    tg = TestGenerator("unsorted_bin_attack")
    h1 = tg.allocate(UNALIGNED_SIZE, 400)
    tg.allocate(UNALIGNED_SIZE, 500)
    tg.deallocate(h1)
    tg.write_after_free(h1, True, [
        (FUZZ_PTR, NULL),
        (FUZZ_PTR, BUFFER_ADDRESS, 0)
    ])
    tg.allocate(UNALIGNED_SIZE, 400)
    tg.finalize()

def test_house_of_einherjar():
    tg = TestGenerator("house_of_einherjar")
    h1 = tg.allocate(UNALIGNED_SIZE, 0x100)
    h2 = tg.allocate(UNALIGNED_SIZE, 0xf8)
    tg.fill_buffer(0,[
        (FUZZ_INT, UNALIGNED_SIZE, 0x100),
        (FUZZ_INT, BUFFER_HEAP_OFFSET, h2, 0, True, -2 * SIZEOF_PTR),
        (FUZZ_PTR, BUFFER_ADDRESS, 0),
        (FUZZ_PTR, BUFFER_ADDRESS, 0),
        (FUZZ_PTR, BUFFER_ADDRESS, 0),
        (FUZZ_PTR, BUFFER_ADDRESS, 0)])

    # Overwriting previous size
    tg.fill_heap(h1, False,
            [(FUZZ_INT, BUFFER_HEAP_OFFSET, h2, 0, True, -2 * SIZEOF_PTR)])
    tg.off_by_one_null(h1)
    tg.deallocate(h2)
    tg.allocate(UNALIGNED_SIZE, 0x180)
    tg.finalize()

def test_house_of_orange():
    """This is slightly different from the original house of orange.
    Instead of using the unsorted bin attack to forge _IO_list_all, this
    overwrites the fd and bk of an unsorted chunk (earlier in top chunk)
    to crafts chunk in buffer"""
    tg = TestGenerator("house_of_orange")
    h1 = tg.allocate(UNALIGNED_SIZE, 0x400 - 16)
    # Overflowing top chunk's size
    tg.overflow(h1, [
        (FUZZ_PTR, NULL),
        (FUZZ_INT, UNALIGNED_SIZE, 0xc01)
    ])
    tg.allocate(UNALIGNED_SIZE, 0x1000)
    tg.overflow(h1, [
        (FUZZ_PTR, NULL),
        (FUZZ_INT, UNALIGNED_SIZE, 0xbe1),
        (FUZZ_PTR, NULL),
        (FUZZ_PTR, BUFFER_ADDRESS, 0)])

    tg.fill_buffer(0, [
        (FUZZ_PTR, NULL),
        (FUZZ_INT, UNALIGNED_SIZE, 0x101),
        (FUZZ_PTR, NULL),
        (FUZZ_PTR, BUFFER_ADDRESS, 0)
    ])
    tg.allocate(UNALIGNED_SIZE, 0xbe0 - 0x10)
    tg.allocate(UNALIGNED_SIZE, 0x101 - 0x10)
    tg.finalize()

test_fastbin_dup()
test_fastbin_dup_into_stack()
test_unsafe_unlink()
test_house_of_spirit()
test_poison_null_byte()
test_house_of_lore()
test_overlapping_chunks()
test_overlapping_chunks_2()
test_house_of_force()
test_unsorted_bin_attack()
test_house_of_einherjar()
test_house_of_orange()
