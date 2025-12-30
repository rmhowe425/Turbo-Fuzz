import claripy
from claripy.ast import BV
from angr import options, Project, SimState, BP_BEFORE


class Fuzzer:
    """
    Interfaces with the Angr API to generate
    new seeds for AFL to increase coverage.
    """

    def __init__(self, config: dict[str, str]):
        self.project = Project(thing=config['target_binary'],
                               auto_load_libs=False
                               )

    def build_angr_state(self, frontier_seed: bytes) -> dict:
        """
        Builds an angr state that calls LLVMFuzzerTestOneInput
        with the given frontier seed.

        Parameters
        ----------
        frontier_seed : bytes
            The concrete bytes from a frontier seed (from AFL++ queue).
        Returns
        -------
        Dictionary containing the angr state object and the symbolic buffer.
        """
        # Frontier seed bytes
        input_bytes = frontier_seed
        input_len = len(input_bytes)

        # Create a symbolic buffer for the input
        symbuf = claripy.BVS("symbuf", input_len * 8)

        # Constrain the symbolic buffer to equal the concrete frontier seed
        concrete_bvv = claripy.BVV(input_bytes, input_len * 8)

        # Find the fuzz target function address
        fuzz_func = self.project.loader.find_symbol("LLVMFuzzerTestOneInput")
        if fuzz_func is None:
            raise RuntimeError("Could not find LLVMFuzzerTestOneInput in binary")

        fuzz_addr = fuzz_func.rebased_addr

        # Build a call_state for the harness function with (symbuf, input_len)
        state = self.project.factory.call_state(
            fuzz_addr,
            symbuf,
            input_len
        )

        # Apply safety & performance options
        state.options.add(options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(options.NO_SYMBOLIC_JUMP_RESOLUTION)

        # Pre‑constrain buffer so it initially matches the frontier seed
        state.solver.add(symbuf == concrete_bvv)

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
