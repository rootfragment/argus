import time

while True:
    try:
        with open("/proc/syscall_integrity", "r") as f:
            flag = int(f.readline().strip())

            if flag == 0:
                print("No issues with the syscall table since module load.")
            
            elif flag == -1:
                print("Syscall discrepancy detected. Printing hooked calls:")
                for line in f:
                    print(line.strip().split('+')[0])

    except FileNotFoundError:
        print("Proc file not found. Is the module loaded?")
    
    except Exception as e:
        print(f"Error reading proc file: {e}")

    time.sleep(10)

