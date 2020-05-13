
import logging
import os

import revenge

logger = logging.getLogger(__name__)
types = revenge.types


here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

basic_constraints = os.path.join(bin_location, "basic_constraints_64.exe")


def test_angr_symbion_x86_64():
    process = revenge.Process(basic_constraints, resume=False, verbose=False)

    # Just for fun, let's start part way in
    begin = process.memory[0x4015af]
    begin.breakpoint = True

    process.resume()

    t = list(process.threads)[0]
    while not t.pc == begin.address:
        t = list(process.threads)[0]

    def fgets_hook(state):
        state.regs.r8 = 0

    simgr = t.angr.simgr

    # Force to stdin
    t.angr.project.hook(0x4015e6, fgets_hook, length=0)
    t.angr.project.hook(0x401650, fgets_hook, length=0)

    avoid = [0x401613, 0x40167d]
    find = [0x40166f]

    puts = process.memory['puts']

    # Checking our custom rehooking is working
    assert t.angr.project._sim_procedures[puts.address].display_name == 'puts'

    simgr.explore(find=find, avoid=avoid)
    assert len(simgr.found) == 1
    assert simgr.found[0].posix.dumps(3) == b"31337 \xba\xb333337 \xba\xb3"

    process.quit()
