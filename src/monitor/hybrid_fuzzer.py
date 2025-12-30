import claripy
from src.io import io
from claripy.ast import BV
from angr.errors import SimEngineError
from angr import exploration_techniques, options, Project, SimFile, SimState, BP_BEFORE


class Fuzzer:
    """
    Interfaces with the Angr API to generate
    new seeds for AFL to increase coverage.
    """

    def __init__(self, config: dict[str, str]):
        self.project = Project(thing=config['target_binary'],
                               auto_load_libs=False
                               )

    def build_angr_state(self, f_path: str) -> dict:
        """
        Builds an angr state that calls LLVMFuzzerTestOneInput with
        a symbolic byte buffer and symbolic size.
        """

        # size of symbolic input (tune as needed)
        SYM_BUFFER_SIZE = 256

        # Create symbolic buffer & symbolic size
        symbuf = claripy.BVS("symbuf", 8 * SYM_BUFFER_SIZE)
        symsize = claripy.BVS("symsize", 64)  # size_t is 64 bits on most systems

        # Find the address of the fuzz target function
        fuzz_sym = self.project.loader.find_symbol("LLVMFuzzerTestOneInput")
        if fuzz_sym is None:
            raise RuntimeError("Could not find LLVMFuzzerTestOneInput symbol")
        fuzz_addr = fuzz_sym.rebased_addr

        # Create a call_state that simulates calling the function
        # with (symbuf, symsize) arguments
        state = self.project.factory.call_state(
            fuzz_addr,
            symbuf,
            symsize,
        )

        # Safety options to reduce solver blow‑up
        state.options.add(options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(options.NO_SYMBOLIC_JUMP_RESOLUTION)

        # You could also constrain symsize if desired:
        # state.solver.add(symsize <= SYM_BUFFER_SIZE)

        return {"state": state, "bit vector": symbuf}

    def create_branch_hook(self, state: SimState) -> dict:
        """
        Creates a list of control flow transitions in the
        Angr state object.

        Parameters
        ----------
        state : SimState
            AFL++ harness execution state after running a frontier
            seed against the harness.

        Returns
        -------
        Dictionary containing Angr state and list of
        control flow transitions.
        """
        fork_log = []
        MAX_BRANCHES = 200

        def on_fork(state):
            if len(fork_log) >= MAX_BRANCHES:
                return
            guard = state.inspect.condition
            target = state.inspect.true_target
            fork_log.append((state.addr, guard, target))

        state.inspect.b(
            "fork",
            when=BP_BEFORE,
            action=on_fork
        )

        return {'state': state, 'branch log': fork_log}

    def execute_simulation_manager(self, state: SimState) -> SimState:
        """
        Bounded symbolic execution that drops
        states which errored or have symbolic IP.
        """
        simgr = self.project.factory.simgr(state)

        # Bound the search to shallow execution
        MAX_STEPS = 200
        MAX_ACTIVE = 40
        steps = 0

        while simgr.active and steps < MAX_STEPS:
            # Step them forward
            simgr.step()

            # Drop any states that error during stepping
            errored_records = list(simgr.errored)
            for rec in errored_records:
                bad = rec.state
                simgr.drop(lambda s: s is bad, stash="active")

            # Drop states with symbolic instruction pointer
            simgr.drop(lambda s: s.solver.symbolic(s.regs.ip), stash="active")

            # Limit active state count
            if len(simgr.active) > MAX_ACTIVE:
                simgr.active = simgr.active[:MAX_ACTIVE]

            steps += 1

        return state

    def generate_new_seeds(self,
                           state: SimState,
                           branch_log: list,
                           sym_stdin: BV
                           ) -> list[bytes]:
        """
        Creates new seeds to be used by AFL++ to increase
        fuzzing coverage.

        Parameters
        ----------
        state : SimState
            AFL++ harness execution state after running a frontier
            seed against the harness.
        branch_log : list
            List of angr control flow transitions associated
            with a program state.
        sym_stdin : BV
            Bit vector created from the contents of a frontier seed.

        Returns
        -------
        seeds : list[bytes]
            List of new seeds to be used by AFL++
            to increase fuzzing coverage.
        """
        seeds = []
        input_len = len(sym_stdin) // 8

        for _, cond, _ in branch_log:
            if cond.is_true() or cond.is_false():
                continue

            state_copy = state.copy()
            state_copy.preconstrainer.remove_preconstraints()
            flipped = claripy.Not(cond)
            state_copy.solver.add(flipped)
            state_copy.solver.timeout = 2000

            if state_copy.solver.satisfiable():
                simfile = state_copy.fs.get("input.xls")
                new_input = state_copy.solver.eval(simfile.load(0, input_len),
                                                   cast_to=bytes
                                                   )
                seeds.append(new_input)

        return list(set(seeds))
