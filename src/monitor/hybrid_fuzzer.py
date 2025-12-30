import claripy
from src.io import io
from claripy.ast import BV
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
        Creates an Angr state object based on an AFL++
        harness and a frontier seed.

        Parameters
        ----------
        f_path : str
            File path to the chosen frontier harness.

        Returns
        -------
        Dictionary containing the Angr state object and bit vector.
        """
        queue_dir = '/queue'
        frontier_seed = io.get_frontier_seed(f_path=f_path + queue_dir)

        if not frontier_seed:
            raise RuntimeError("`frontier_seed` cannot be an empty string.")

        input_bytes = io.read_frontier_seed(f_path=frontier_seed)
        sym_file = claripy.BVS("xls_file", len(input_bytes) * 8)
        concrete_bvv = claripy.BVV(input_bytes, len(input_bytes) * 8)
        state = self.project.factory.full_init_state(
            args=["prog", "input.xls"]
        )
        state.options.add(options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

        state.fs.insert(
            "input.xls",
            SimFile(
                name="input.xls",
                content=sym_file,
                size=len(input_bytes),
                has_end=True
            )
        )
        state.preconstrainer.preconstrain(sym_file, concrete_bvv)
        return {'state': state, 'bit vector': sym_file}

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
        Creates a simulation manager and initiates symbolic
        execution against our state object.

        Parameters
        ----------
        state: SimState
            AFL++ harness execution state after running a frontier
            seed against the harness.

        Returns
        -------
        Updated state object.
        """
        steps = 0
        MAX_ACTIVE = 40
        MAX_STEPS = 200
        simgr = self.project.factory.simgr(state)
        simgr.use_technique(exploration_techniques.Veritesting())
        simgr.use_technique(exploration_techniques.LoopSeer(bound=4))

        while simgr.active and steps < MAX_STEPS:
            simgr.step()
            steps += 1

            if len(simgr.active) > MAX_ACTIVE:
                simgr.active = simgr.active[:MAX_ACTIVE]

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

        return seeds
