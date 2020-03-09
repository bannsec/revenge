
import logging

logger = logging.getLogger(__name__)

import os
import pytest
import revenge
types = revenge.types

from time import sleep

import r2pipe

from revenge.plugins.radare2.decompilers.ghidra import GhidraDecompiler

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

basic_one_path = os.path.join(bin_location, "basic_one")
basic_one_ia32_nopie_path = os.path.join(bin_location, "basic_one_ia32_nopie")

def test_r2_ghidra_decompile_pie64_function():

    process = revenge.Process(basic_one_path, resume=False, verbose=False)

    process.radare2.analyze()
    sleep(0.2)

    process.radare2._r2.cmd("s main")
    main = int(process.radare2._r2.cmd("s"), 16)

    # Force the r2 decompiler
    process.radare2.decompiler = "ghidra"
    assert isinstance(process.radare2.decompiler, GhidraDecompiler)

    # Force decompiler plugin to use it
    process.decompiler.imp = process.radare2.decompiler
    assert isinstance(process.decompiler.imp, GhidraDecompiler)

    d = process.decompiler.decompile_function("basic_one:" + hex(main))

    print(d)
    repr(d)
    
    timeless = process.techniques.NativeTimelessTracer()
    timeless.apply()
    t = list(timeless)[0]

    process.memory[process.entrypoint].breakpoint = False
    t.wait_for("basic_one:0x692")

    # Highlight our path
    d.highlight(t, "green")

    # Make sure this can print
    s = str(d)
    print(s)
    assert "\x1b[42m" + hex(process.memory['basic_one:0x692'].address) in s

    assert 0x66d in d
    assert d[0x66d].address == 0x66d
    assert d[0x66d].highlight == 'GREEN'
    assert b"func" in d[0x66d].src

    process.quit()

def test_r2_ghidra_decompile_nonpie32_function():

    process = revenge.Process(basic_one_ia32_nopie_path, resume=False, verbose=False)

    process.radare2.analyze()
    sleep(0.2)

    process.radare2._r2.cmd("s main")
    main = int(process.radare2._r2.cmd("s"), 16)

    # Force the r2 decompiler
    process.radare2.decompiler = "ghidra"
    assert isinstance(process.radare2.decompiler, GhidraDecompiler)

    # Force decompiler plugin to use it
    process.decompiler.imp = process.radare2.decompiler
    assert isinstance(process.decompiler.imp, GhidraDecompiler)

    d = process.decompiler['basic_one_ia32_nopie:main']

    print(d)
    repr(d)
    
    timeless = process.techniques.NativeTimelessTracer()
    timeless.apply()
    t = list(timeless)[0]

    process.memory[process.entrypoint].breakpoint = False
    t.wait_for(0x08048489)

    # Highlight our path
    d.highlight(t, "cyan")

    # Make sure this can print
    s = str(d)
    print(s)
    assert "\x1b[46m0x8048489" in s

    mod, off = process.modules.lookup_offset(0x8048460)

    assert off in d
    assert d[off].highlight == 'CYAN'
    assert d[off].address == off
    assert b"func" in d[off].src

    process.quit()

