# ------------------------------------------------------------------------------
# std imports
# ------------------------------------------------------------------------------
import argparse
import logging
import os
import subprocess
import time
import requests
# ------------------------------------------------------------------------------
# imports
# ------------------------------------------------------------------------------
import psutil
import tqdm
# ------------------------------------------------------------------------------
# create_waflz_instance
# ------------------------------------------------------------------------------
def create_waflz_instance( a_waflz_args ):
    """
    creates a walfz instance and returns the subprocess

    Parameters
    ----------
    a_waflz_args: list[Str]
        args to pass to waflz

    Returns
    -------
    subprocess.Popen
        the waflz subprocess

    Raises
    ------
    None
    """
    # ------------------------------------------------------
    # waflz location relative to this file
    # ------------------------------------------------------
    l_file_path = os.path.abspath(__file__)
    l_test_dir = os.path.dirname(os.path.dirname(l_file_path))
    l_dir_location = os.path.dirname(l_test_dir)
    l_waflz_location = f"{l_dir_location}/build/util/waflz_server/waflz_server"
    # ------------------------------------------------------
    # default waflz args
    # ------------------------------------------------------
    l_args = [
        "-d", f"{l_test_dir}/data/waf/conf",
        "-r", f"{l_test_dir}/data/waf/ruleset",
        "-b", f"{l_test_dir}/data/waf/conf/scopes",
        "-Q", f"{l_test_dir}/data/bot/known_bot_info.json",
    ]
    # ------------------------------------------------------
    # remove any args from l_args that are repeated in 
    # a_waflz_args
    # ------------------------------------------------------
    for i_flag, i_value in zip(l_args[0::2], l_args[1::2]):
        if i_flag in a_waflz_args:
            logging.debug("removing default: %s %s", i_flag, i_value)
            l_args.remove(i_flag)
            l_args.remove(i_value)
    # ------------------------------------------------------
    # create the command to run
    # ------------------------------------------------------
    l_cmd = [l_waflz_location, *l_args]
    # ------------------------------------------------------
    # add the passed in args
    # ------------------------------------------------------
    l_cmd.extend(a_waflz_args)
    # ------------------------------------------------------
    # create and return waflz subprocess
    # ------------------------------------------------------
    logging.debug("running command: %s", ' '.join(l_cmd))
    ao_subprocess = subprocess.Popen(l_cmd)
    return ao_subprocess      
# ------------------------------------------------------------------------------
# wait_for_waflz_to_load
# ------------------------------------------------------------------------------
def wait_for_waflz_to_load( a_waflz_process, a_max_time=30, a_progress=True ):
    """
    waits for the given waflz process to load or until the max_time is reached.

    Parameters
    ----------
    a_waflz_process: subprocess.Popen
        A waflz subprocess

    a_max_time: int
        the max time allowed to wait before timeout 

    a_progress: bool
        flag to show display on screen

    Returns
    -------
    float
        the time in seconds it took for waflz to load

    Raises
    ------
    None
    """
    # ------------------------------------------------------
    # variables to track memory growth over time
    # ------------------------------------------------------
    l_last_seen = None
    l_current = 0
    # ------------------------------------------------------
    # get the range of seconds to wait
    # (and progress bar if a_progress set)
    # ------------------------------------------------------
    logging.info("Waiting on waflz to load...")
    l_progress = tqdm.tqdm(range(a_max_time)) if a_progress else range(a_max_time)
    # ------------------------------------------------------
    # start timer
    # ------------------------------------------------------
    l_start_time = time.perf_counter()
    # ------------------------------------------------------
    # loop for each second up till max time allowed
    # ------------------------------------------------------
    for _ in l_progress:
        # --------------------------------------------------
        # allow waflz to load for a second
        # --------------------------------------------------
        time.sleep(1)
        # --------------------------------------------------
        # set previous memory seen to the current
        # --------------------------------------------------
        l_last_seen = l_current
        # --------------------------------------------------
        # get current memory usage
        # --------------------------------------------------
        l_current = get_memory_usage_in_mb(a_waflz_process.pid)
        # --------------------------------------------------
        # update progress bar if being shown
        # --------------------------------------------------
        if a_progress:
            l_progress.set_postfix(
                last_memory_seen=str(l_last_seen) + "MB",
                current_memory=str(l_current) + "MB"
            )
        # --------------------------------------------------
        # if there was no change, break - done loading
        # --------------------------------------------------
        if l_current == l_last_seen:
            break
    # ------------------------------------------------------
    # return the time it took to load
    # ------------------------------------------------------
    return time.perf_counter() - l_start_time
# ------------------------------------------------------------------------------
# get_memory_usage_in_mb
# ------------------------------------------------------------------------------
def get_memory_usage_in_mb( a_pid ):
    """
    gets the memory in megabytes for a given process.

    Parameters
    ----------
    a_pid: int
        A process id

    Returns
    -------
    float
        the memory in megabytes that the process is using

    Raises
    ------
    None
    """
    # ------------------------------------------------------
    # get the rss of the process and return in MB
    # ------------------------------------------------------
    l_process = psutil.Process(a_pid)
    return round(l_process.memory_info().rss / 1024 ** 2, 2)
# ------------------------------------------------------------------------------
# print_waflz_stats
# ------------------------------------------------------------------------------
def get_average_request_time_for_waflz(a_trials=5):
    """
    gets the average time walfz took to respond to requests.

    Parameters
    ----------
    a_trials: int
        the amount of request to send to waflz

    Returns
    -------
    float
        the average time it took to perform the request

    Raises
    ------
    None
    """
    # ------------------------------------------------------
    # total time for all request
    # ------------------------------------------------------
    l_total_time = 0
    # ------------------------------------------------------
    # do <a_trials> test
    # ------------------------------------------------------
    for _ in range(a_trials):
        start_time = time.perf_counter()
        response = requests.get("http://localhost:12345/test.html")
        assert response.status_code == 200
        l_total_time += time.perf_counter() - start_time
    # ------------------------------------------------------
    # return average time
    # ------------------------------------------------------
    return l_total_time / a_trials
# ------------------------------------------------------------------------------
# print_waflz_stats
# ------------------------------------------------------------------------------
def print_waflz_stats(a_final_mem_usage, a_avg_rqst_time, a_seconds, a_max_time):
    """
    prints the time and memory used for waflz to load.

    Parameters
    ----------
    a_final_mem_usage: float
        the memory usage for waflz

    a_avg_rqst_time: float
        average time for request to waflz

    a_seconds: int
        the time it took for waflz to load

    a_max_time: float
        the max amount of time allowed to load

    Returns
    -------
    None

    Raises
    ------
    None
    """
    # ------------------------------------------------------
    # check if the process got a chance to finish loading
    # ------------------------------------------------------
    l_was_forced = a_seconds >= a_max_time
    l_was_forced_str = "(Forced)" if l_was_forced else ""
    # ------------------------------------------------------
    # print stats
    # ------------------------------------------------------
    print()
    print(f"============ Stats ============")
    print(f"Loading Time : {a_seconds:.0f}s {l_was_forced_str}")
    print(f"Total RSS    : {a_final_mem_usage:.2f}MB")
    print(f"Avg rqst time: {a_avg_rqst_time:.2f}s")
    print("===============================")
    print()
# ------------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------------
def get_waflz_memory_usage( a_max_time, a_trials, a_waflz_args ):
    """
    creates a waflz process and measures load time and memory

    Parameters
    ----------
    a_max_time: float
        the max amount of time allowed to load

    a_trials: int
        the amount of request to send to waflz

    a_waflz_args: list[Str]
        args to pass to waflz

    Returns
    -------
    None
    
    Raises
    ------
    None
    """
    # ------------------------------------------------------
    # create waflz instance
    # ------------------------------------------------------
    l_waflz = create_waflz_instance(a_waflz_args)
    # ------------------------------------------------------
    # wait for waflz to load
    # ------------------------------------------------------
    l_show_pbar = logging.root.level != logging.WARNING
    l_seconds = wait_for_waflz_to_load(l_waflz, a_max_time, l_show_pbar)
    # ------------------------------------------------------
    # get the final memory usage for waflz
    # ------------------------------------------------------
    l_final_mem_usage = get_memory_usage_in_mb(l_waflz.pid)
    # ------------------------------------------------------
    # get average request time for waflz
    # ------------------------------------------------------
    l_avg_rqst_time = get_average_request_time_for_waflz(a_trials)
    # ------------------------------------------------------
    # print stats for load/memory usage
    # ------------------------------------------------------
    print_waflz_stats(l_final_mem_usage, l_avg_rqst_time, l_seconds, a_max_time)
    # ------------------------------------------------------
    # kill waflz 
    # ------------------------------------------------------
    l_waflz.kill()
# ------------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------------
def main():
    """main function"""
    arg_parser = argparse.ArgumentParser(
        description="Performs a load test on waflz.",
        usage="%(prog)s",
        epilog=""
    )
    # ------------------------------------------------------
    # arguments for file
    # ------------------------------------------------------
    arg_parser.add_argument(
        "-m",
        "--max_time",
        dest="max_time",
        help="max time allowed for waflz to load (default 30s)",
        type=int,
        default=30,
        required=False
    )
    arg_parser.add_argument(
        "-lt",
        "--load_trials",
        dest="trails",
        help="amount of request to send to waflz (default 5)",
        type=int,
        default=5,
        required=False
    )
    arg_parser.add_argument(
        "-lv",
        "--load_verbose",
        action="store_const",
        dest="verbose",
        help="prints output to screen",
        const=True,
        default=False,
        required=False
    )
    arg_parser.add_argument(
        "-ld",
        "--load_debug",
        action="store_const",
        dest="debug",
        help="prints debug to screen",
        const=True,
        default=False,
        required=False
    )
    l_args, l_waflz_args = arg_parser.parse_known_args()
    # ------------------------------------------------------
    # get logging level
    # ------------------------------------------------------
    l_log_level = logging.WARNING
    if l_args.verbose: l_log_level = logging.INFO
    if l_args.debug: l_log_level = logging.DEBUG
    # ------------------------------------------------------
    # set logger config
    # ------------------------------------------------------
    logging.basicConfig(
        level=l_log_level,
        format="%(levelname)s:%(funcName)s:%(message)s"
    )
    # ------------------------------------------------------
    # run script
    # ------------------------------------------------------
    get_waflz_memory_usage(l_args.max_time, l_args.trails, l_waflz_args)
# ------------------------------------------------------------------------------
# from cmd line
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
# ------------------------------------------------------------------------------
# NOTE: you can pass anything you want to this script and it will get passed
# to waflz. so while it test on the test data we have here, you can make it 
# test on the production data by passing in the needed args
#
# ex: 
# python3 ./tests/load/memory.py 
#   -d /oc/local/waf/conf/ 
#   -r /oc/local/waf/ruleset/ 
#   -b /oc/local/waf/conf/scopes 
#   -U /oc/local/waf/bot/bot_data/known_bot_ua.json 
#   -K /oc/local/waf/bot/bot_data/known_bot_ips.json
# ------------------------------------------------------------------------------
