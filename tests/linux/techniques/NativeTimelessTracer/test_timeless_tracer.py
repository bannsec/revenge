import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

timeless_one_path = os.path.join(bin_location, "timeless_one")
timeless_two_path = os.path.join(bin_location, "timeless_two")
timeless_two_i386_path = os.path.join(bin_location, "timeless_two_i386")

#
# i386
#

def test_timeless_basic_two_i386():

    p = revenge.Process(timeless_two_i386_path, resume=False, verbose=False)

    timeless = p.techniques.NativeTimelessTracer()
    timeless.apply()
    t = timeless.traces[list(timeless)[0]]
    p.memory[p.entrypoint].breakpoint = False

    end_of_main = p.memory['timeless_two_i386:0x554'].address
    t.wait_for(end_of_main)

    insts = iter(t)

    begin_main = p.memory['timeless_two_i386:0x511'].address
    while int(next(insts).context.pc) != begin_main:
        pass

    timeless_two = p.modules['timeless_two_i386']

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x512
    depth = inst.depth
    assert depth is not None

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x514
    assert inst.depth == depth

    depth += 1

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x555
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x558
    assert inst.depth == depth

    depth -= 1

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x519
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x51e
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x524
    assert inst.depth == depth
    assert inst.context.edx.memory_range.readable == True
    assert inst.context.edx.next.thing == "Test string"

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x52A
    assert inst.depth == depth
    assert inst.context.ecx.memory_range.readable == True
    assert inst.context.ecx.next.memory_range.readable == True
    assert inst.context.ecx.next.next.thing == "Test string"

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x530
    assert inst.depth == depth
    assert inst.context.eax.memory_range.readable == True
    assert inst.context.eax.next.memory_range.readable == True
    assert inst.context.eax.next.next.thing == "Test string"

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x535
    assert inst.depth == depth
    assert int(inst.context.eax) == 1

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x53a
    assert inst.depth == depth
    assert int(inst.context.ebx) == 2

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x53f
    assert inst.depth == depth
    assert int(inst.context.ecx) == 3

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x544
    assert inst.depth == depth
    assert int(inst.context.edx) == 4

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x549
    assert inst.depth == depth
    assert int(inst.context.edi) == 5

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x54e
    assert inst.depth == depth
    assert int(inst.context.esi) == 6

    depth += 1

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x4fd
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x4fe
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x500
    assert inst.depth == depth

    depth += 1

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x555
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x558
    assert inst.depth == depth

    depth -= 1

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x505
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x50a
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x50f
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x510
    assert inst.depth == depth

    depth -= 1

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x553
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x554
    assert inst.depth == depth
    assert int(inst.context.eax) == 1337

    p.quit()

#
# x64
#

def test_timeless_basic_two_amd64():

    p = revenge.Process(timeless_two_path, resume=False, verbose=False)

    timeless = p.techniques.NativeTimelessTracer()
    timeless.apply()
    t = timeless.traces[list(timeless)[0]]
    p.memory[p.entrypoint].breakpoint = False

    end_of_main = p.memory['timeless_two:0x6BB'].address
    t.wait_for(end_of_main)

    insts = iter(t)

    begin_main = p.memory['timeless_two:0x635'].address
    while int(next(insts).context.pc) != begin_main:
        pass

    timeless_two = p.modules['timeless_two']

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x636
    depth = inst.depth
    assert depth is not None

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x639
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x640
    assert inst.context.rax.memory_range.readable == True
    assert inst.context.rax.next.thing == "Test string"
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x647
    assert inst.context.rdx.memory_range.readable == True
    assert inst.context.rdx.next.memory_range.readable == True
    assert inst.context.rdx.next.next.thing == "Test string"
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x64E
    assert inst.context.rcx.memory_range.readable == True
    assert inst.context.rcx.next.memory_range.readable == True
    assert inst.context.rcx.next.next.thing == "Test string"
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x655
    assert inst.context.rax.thing == 1
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x65C
    assert inst.context.rbx.thing == 2
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x663
    assert inst.context.rcx.thing == 3
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x66A
    assert inst.context.rdx.thing == 4
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x671
    assert inst.context.rdi.thing == 5
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x678
    assert inst.context.rsi.thing == 6
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x67F
    assert inst.context.r8.thing == 7
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x686
    assert inst.context.r9.thing == 8
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x68d
    assert inst.context.r10.thing == 9
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x694
    assert inst.context.r11.thing == 10
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x69b
    assert inst.context.r12.thing == 11
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x6a2
    assert inst.context.r13.thing == 12
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x6a9
    assert inst.context.r14.thing == 13
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x6b0
    assert inst.context.r15.thing == 14
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x6B5
    assert inst.context.rax.thing == 0
    assert inst.depth == depth

    depth += 1

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x62A
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x62B
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x62e
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x633
    assert inst.depth == depth

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x634
    assert inst.depth == depth

    depth -= 1

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x6BA
    assert inst.depth == depth
    assert int(inst.context.rax) == 1337

    inst = next(insts)
    assert int(inst.context.pc) == timeless_two.base + 0x6BB
    assert inst.depth == depth

    p.quit()

def test_timeless_basic_amd64():

    p = revenge.Process(timeless_one_path, resume=False, verbose=False)

    timeless = p.techniques.NativeTimelessTracer()
    repr(timeless)
    str(timeless)

    timeless.apply()
    t = timeless.traces[list(timeless)[0]]
    p.memory[p.entrypoint].breakpoint = False

    # Right after decrypting
    after_call = p.memory['timeless_one:0x6F5'].address
    ti = t.wait_for(after_call)
    assert ti.context.rax.next.thing == "SuperS3cretFl@g"
    assert int(ti.context.pc) == after_call

    repr(timeless)
    str(timeless)

    repr(t)
    str(t)

    for ti in t:
        repr(ti)
        str(ti)

    p.quit()
