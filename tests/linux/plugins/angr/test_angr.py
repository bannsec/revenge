
import logging
import os

import revenge

logger = logging.getLogger(__name__)
types = revenge.types


here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

basic_constraints = os.path.join(bin_location, "basic_constraints")
basic_constraints_i686 = os.path.join(bin_location, "basic_constraints_i686")


def test_angr_basic():
    process = revenge.Process(basic_constraints, resume=False, verbose=False)

    # Just for fun, let's start part way in
    begin = process.memory['basic_constraints:0x11f3']
    begin.breakpoint = True

    process.memory[process.entrypoint].breakpoint = False

    t = list(process.threads)[0]
    while not t.pc == begin.address:
        t = list(process.threads)[0]

    project = t.angr.project
    # Caching
    assert project is t.angr.project
    state = t.angr.state
    assert state is not t.angr.state
    assert state.solver.eval(state.ip) == begin.address

    simgr = t.angr.simgr
    assert simgr is not t.angr.simgr
    assert state.solver.eval(simgr.active[0].ip) == begin.address

    # Should reload project file
    project = t.angr.project
    t.angr.load_options = {'auto_load_libs': False}
    assert t.angr.project is not project

    # Should reload project file
    project = t.angr.project
    t.angr.use_sim_procedures = False
    assert t.angr.project is not project

    # Should reload project file
    project = t.angr.project
    t.angr.exclude_sim_procedures_list = []
    assert t.angr.project is not project

    # Should reload project file
    project = t.angr.project
    t.angr.support_selfmodifying_code = True
    assert t.angr.project is not project

    # Basic reg read and mem read
    assert state.solver.eval(state.regs.rax) == 0xb3ba203733333133
    assert state.mem[int(process.memory['basic_constraints:0x201b'].address)].string.concrete == b'Success 1!'

    assert process.threads._breakpoint_original_bytes[begin.address] == b"\x48\x8d\x3d\x0a\x0e\x00\x00\xe8\x41\xfe\xff\xff\x48\x8b\x15\x0a"

    process.quit()


def test_angr_symbion_x86_64():
    process = revenge.Process(basic_constraints, resume=False, verbose=False)

    # Just for fun, let's start part way in
    begin = process.memory['basic_constraints:0x11f3']
    begin.breakpoint = True

    process.memory[process.entrypoint].breakpoint = False

    t = list(process.threads)[0]
    while not t.pc == begin.address:
        t = list(process.threads)[0]

    simgr = t.angr.simgr
    avoid = [
        process.memory['basic_constraints:0x1241'].address,
        process.memory['basic_constraints:0x12a5'].address]
    find = [process.memory['basic_constraints:0x1297'].address]

    basic = process.modules['basic_constraints']

    # Checking our custom rehooking is working
    assert t.angr.project._sim_procedures[int(basic.symbols['plt.puts'].address)].display_name == 'puts'

    simgr.explore(find=find, avoid=avoid)
    assert len(simgr.found) == 1
    assert simgr.found[0].posix.dumps(0) == b"31337 \xba\xb333337 \xba\xb3"

    process.quit()


def test_angr_symbion_i686():
    process = revenge.Process(basic_constraints_i686, resume=False, verbose=False)

    # Just for fun, let's start part way in
    begin = process.memory[0x0804855c]
    begin.breakpoint = True

    process.memory[process.entrypoint].breakpoint = False

    t = list(process.threads)[0]
    while not t.pc == begin.address:
        t = list(process.threads)[0]

    simgr = t.angr.simgr
    avoid = [
        process.memory[0x80485ab].address,
        process.memory[0x8048620].address]
    find = [process.memory[0x804860c].address]

    basic = process.modules['basic_constraints_i686']

    # Checking our custom rehooking is working
    assert t.angr.project._sim_procedures[int(basic.symbols['plt.puts'].address)].display_name == 'puts'

    simgr.explore(find=find, avoid=avoid)
    assert len(simgr.found) == 1
    assert simgr.found[0].posix.dumps(0) == b"31337 \xba\xb333337 \xba\xb3"

    process.quit()
