import claripy
from io import io
from claripy.ast import BV
from angr import Project, SimFileStream, SimState, BP_BEFORE


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
        queue_dir = '/queue1'
        frontier_seed = io.get_frontier_seed(f_path=f_path + queue_dir)

        if not frontier_seed:
            raise RuntimeError("`frontier_seed` cannot be an empty string.")

        input_bytes = io.read_frontier_seed(f_path=frontier_seed)
        sym_stdin = claripy.BVS("stdin", len(input_bytes) * 8)
        state = self.project.factory.full_init_state(
            stdin=SimFileStream(
                name="input.xls",
                content=sym_stdin
            )
        )
        state.preconstrainer.preconstrain(sym_stdin, input_bytes)
        return {'state': state, 'bit vector': sym_stdin}

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
        branch_log = []

        def branch_inspect(state):
            guard = state.inspect.condition
            target = state.inspect.true_target
            branch_log.append((state.addr, guard, target))

        state.inspect.b(
            "branch",
            when=BP_BEFORE,
            action=branch_inspect
        )

        return {'state': state, 'branch log': branch_log}

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
        simgr = self.project.factory.simgr(state)
        simgr.run()
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

            if state_copy.solver.satisfiable():
                new_input = state_copy.solver.eval(state_copy.posix.stdin.load(0, input_len),
                                                   cast_to=bytes
                                                   )
                seeds.append(new_input)

        return seeds
