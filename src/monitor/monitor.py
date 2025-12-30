import logging
from src.io import io
from datetime import datetime
from src.monitor.hybrid_fuzzer import Fuzzer

logging.basicConfig(filename="fuzz-monitor.log",
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    filemode='a',
                    )

class Monitor:
    """
    Monitors fuzzing code coverage.
    Leverages Angr to enrich fuzzer seed corpus when coverage has plateaued.
    """

    def __init__(self):
        self.config = io.read_config()
        self.curr_time = datetime.now()
        self.fuzzer = Fuzzer(config=self.config)

    def _check_fuzzer_plateau(self, metrics: dict[str, str]) -> bool:
        """
        Checks AFL++ fuzzer stats to determine whether coverage
        has plateaued within the past 1 hour.

        Parameters
        ----------
        metrics : dict[str, str]
            AFL++ fuzzer metrics.

        Returns
        -------
        True if coverage has plateaued.
        False if coverage has not plateaued.
        """
        delta = 1  # hours
        last_find = datetime.fromtimestamp(int(metrics['last_find']))
        diff = self.curr_time - last_find
        return (diff.total_seconds() / 3600) > delta

    def monitor_afl(self):
        """
        Monitors fuzzing coverage for all fuzzers
        to determine whether seed corpus enrichment is needed.
        """
        sanitizers = list(self.config.keys())[1:]

        for sanitizer in sanitizers:
            if not self.config[sanitizer]:
                logging.info(f"[*] Sanitizer `{sanitizer}` not in use.")
                continue

            metrics = io.read_fuzzer_stats(f_path=self.config[sanitizer] + '/fuzzer_stats')

            if not self._check_fuzzer_plateau(metrics=metrics):
                logging.info(f"[*] Symbolic execution needed for {sanitizer}")

                try:
                    state_dict = self.fuzzer.build_angr_state(f_path=self.config[sanitizer])
                    hook_dict = self.fuzzer.create_branch_hook(state=state_dict['state'])
                    state_sim_mgr = self.fuzzer.execute_simulation_manager(state=hook_dict['state'])
                    seeds = self.fuzzer.generate_new_seeds(
                        state=state_sim_mgr,
                        branch_log=hook_dict['branch log'],
                        sym_stdin=state_dict['bit vector']
                    )
                    logging.info(f"[+] {len(seeds)} have been created for {sanitizer}!")
                    io.write_new_seeds(seeds=seeds)
                except Exception as e:
                    logging.error(f"[!] Symbolic execution failed. {str(e)}")
                    raise RuntimeError(f"[!] Symbolic execution failed. {str(e)}")