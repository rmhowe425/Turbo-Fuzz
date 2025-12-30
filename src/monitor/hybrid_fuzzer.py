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
        queue_dir = "/queue"
        frontier_seed = io.get_frontier_seed(f_path=f_path + queue_dir)

        if not frontier_seed:
            raise RuntimeError("`frontier_seed` cannot be empty")

        input_bytes = io.read_frontier_seed(frontier_seed)

        sym_file = claripy.BVS("xls_file", len(input_bytes) * 8)
        concrete_bvv = claripy.BVV(input_bytes, len(input_bytes) * 8)

        # Let angr handle loading & mapping
        state = self.project.factory.entry_state(
            args=["prog", "input.xls"],
            auto_load_libs=True,  # OK here
        )

        # Safety options
        state.options.add(options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(options.NO_SYMBOLIC_JUMP_RESOLUTION)
        state.options.add(options.CONCRETIZE)

        # Insert symbolic input file
        state.fs.insert(
            "input.xls",
            SimFile(
                name="input.xls",
                content=sym_file,
                size=len(input_bytes),
                has_end=True,
            )
        )

        # Correct preconstrain order
        state.preconstrainer.preconstrain(concrete_bvv, sym_file)

        return {
            "state": state,
            "bit vector": sym_file,
        }

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
        simgr = self.project.factory.simgr(state)

        # Use LoopSeer, no Veritesting for safer control-flow
        simgr.use_technique(exploration_techniques.LoopSeer(bound=3))

        MAX_ACTIVE = 40
        MAX_STEPS = 200
        steps = 0

        while simgr.active and steps < MAX_STEPS:
            # Step all active states once
            simgr.step()

            # If any states errored, remove them
            if simgr.errored:
                # For each ErrorRecord, drop its state from active
                for rec in simgr.errored:
                    bad_state = rec.state
                    simgr.drop(lambda s: s is bad_state, stash="active")
                # Clear the errored list to reset
                simgr.errored.clear()

            # Drop any states with symbolic IP to avoid further invalid jumps
            simgr.drop(lambda s: s.solver.symbolic(s.regs.ip), stash="active")

            # Cap active states
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
