#!/usr/bin/env python3

import subprocess
import os

small_file = "./tests/richie_100x100.pbm"
small_repetitions = 100000

normal_file = "./tests/infogebaude.pbm"
normal_repetitions = 1000

big_file = "./tests/mi.pbm"
big_repetitions = 5

tmp_dir = "performance_test_output"

os.mkdir(tmp_dir)

for i in range(3):
    print(f"Testing encoding for version {i} with small file and {small_repetitions} repetitions:")
    # no idea why but somehow if we try to do it the proper way the programs says that the argument count is wrong
    # so this will have to do
    subprocess.Popen(f"./main -V{i} -B{small_repetitions} {small_file} -o {tmp_dir}/v{i}_compressed_small.bin", shell=True).wait()

for i in range(3):
    print(f"\nTesting encoding for version {i} with mid file and {normal_repetitions} repetitions:")
    subprocess.Popen(f"./main -V{i} -B{normal_repetitions} {normal_file} -o {tmp_dir}/v{i}_compressed_normal.bin", shell=True).wait()

for i in range(3):
    print(f"\nTesting encoding for version {i} with big file and {big_repetitions} repetitions:")
    subprocess.Popen(f"./main -V{i} -B{big_repetitions} {big_file} -o {tmp_dir}/v{i}_compressed_big.bin", shell=True).wait()

print("\nDecoding: ")

for i in range(3):
    print(f"\nTesting decoding for version {i} with small file and {small_repetitions} repetitions:")
    subprocess.Popen(f"./main -d -V{i} -B{small_repetitions} {tmp_dir}/v{i}_compressed_small.bin", shell=True).wait()

for i in range(3):
    print(f"\nTesting decoding for version {i} with mid file and {normal_repetitions} repetitions:")
    subprocess.Popen(f"./main -d -V{i} -B{normal_repetitions} {tmp_dir}/v{i}_compressed_normal.bin", shell=True).wait()

for i in range(3):
    print(f"\nTesting decoding for version {i} with big file and {big_repetitions} repetitions:")
    subprocess.Popen(f"./main -d -V{i} -B{big_repetitions}  {tmp_dir}/v{i}_compressed_big.bin", shell=True).wait()

os.system(f"rm -rf {tmp_dir}")