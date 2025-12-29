from src.monitor.monitor import Monitor


def main():
    mon_inst = Monitor()
    mon_inst.monitor_afl()


main()
