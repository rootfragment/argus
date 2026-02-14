# Multi-File Kernel Module Demo 

This README explains **how a single Linux kernel module (`.ko`) is built
from multiple source files**, how they communicate, and how the project
structure works.
All source code has been intentionally removed as requested.

------------------------------------------------------------------------

##  Project Structure

    /demo
     ├─ core.c
     ├─ demo.h
     ├─ part_1.c
     ├─ part_2.c
     ├─ part_3.c
     ├─ Makefile
     └─ README.md

------------------------------------------------------------------------

##  Purpose

This project demonstrates how:

-   multiple `.c` files are compiled into **one kernel module**
-   each file contributes a separate functionality
-   a shared header (`demo.h`) provides the interface between files
-   the main file (`core.c`) calls functions from all parts
-   everything links together into **`demo.ko`**

------------------------------------------------------------------------

##  How the Components Work 

###  demo.h --- Header File

The header file contains declarations of functions that other `.c` files
implement.
It acts as a **shared interface** so each file knows what functions
exist.

###  part_1.c, part_2.c, part_3.c --- Separated Logic

Each file in this group:

-   includes the shared header
-   implements one function (example: `part_1_fun()`)
-   prints a message or performs a small operation when called

These files are isolated and modular, which keeps the code organized and
scalable.

###  core.c --- Main Module Controller

This file contains the kernel module's:

-   **initialization function** (runs on module load)# Multi-File Kernel Module Demo --- 

This README explains **how a single Linux kernel module (`.ko`) is built
from multiple source files**, how they communicate, and how the project
structure works.

------------------------------------------------------------------------

##  Project Structure

    /demo
     ├─ core.c
     ├─ demo.h
     ├─ part_1.c
     ├─ part_2.c
     ├─ part_3.c
     ├─ Makefile
     └─ README.md

------------------------------------------------------------------------

##  Purpose

This project demonstrates how:

-   multiple `.c` files are compiled into **one kernel module**
-   each file contributes a separate functionality
-   a shared header (`demo.h`) provides the interface between files
-   the main file (`core.c`) calls functions from all parts
-   everything links together into **`demo.ko`**

------------------------------------------------------------------------

##  How the Components Work (Without Code)

###  demo.h --- Header File

The header file contains declarations of functions that other `.c` files
implement.
It acts as a **shared interface** so each file knows what functions
exist.

###  part_1.c, part_2.c, part_3.c 
Each file in this group:

-   includes the shared header
-   implements one function (example: `part_1_fun()`)
-   prints a message or performs a small operation when called

These files are isolated and modular, which keeps the code organized and
scalable.

###  core.c --- Main Module Controller

This file contains the kernel module's:

-   **initialization function** (runs on module load)
-   **exit function** (runs on module unload)

It calls the functions implemented in all part files.
This demonstrates how split source files still form a single final
module.

###  Makefile --- How Everything Is Combined

The Makefile tells the Linux kernel build system to:

-   compile each `.c` file into a `.o` object
-   link all objects (`core.o`, `part_1.o`, etc.) together
-   produce a single final output: **`demo.ko`**

------------------------------------------------------------------------

##  How to Build and Use the Module

### Build:

Run the kernel build system with this directory as a module:

    make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

### Load the module:

    sudo insmod demo.ko

### View kernel log output:

    dmesg | tail

You will see messages from:

-   core module init
-   part_1
-   part_2
-   part_3

### Unload:

    sudo rmmod demo

------------------------------------------------------------------------

##  How Everything Works Together

  Component            Purpose
  -------------------- --------------------------------------------------
  **demo.h**           Shares declarations between all `.c` files
  **part_X.c files**   Each implements one function
  **core.c**           Calls all functions and handles module lifecycle
  **Makefile**         Combines all files into a single `.ko`

Even though there are multiple C source files, the final result is **one
kernel module**.

------------------------------------------------------------------------

##  Summary

This demo illustrates:

-   modular file structure
-   clean separation of functionality
-   unified build output
-   scalable design for larger kernel frameworks

This structure is ideal for real-world kernel projects such as
monitoring frameworks, security tools, or debugging modules.
-   **exit function** (runs on module unload)

It calls the functions implemented in all part files.
This demonstrates how split source files still form a single final
module.

###  Makefile --- How Everything Is Combined

The Makefile tells the Linux kernel build system to:

-   compile each `.c` file into a `.o` object
-   link all objects (`core.o`, `part_1.o`, etc.) together
-   produce a single final output: **`demo.ko`**

------------------------------------------------------------------------

##  How to Build and Use the Module

### Build:

Run the kernel build system with this directory as a module:

    make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

### Load the module:

    sudo insmod demo.ko

### View kernel log output:

    dmesg | tail

You will see messages from:

-   core module init
-   part_1
-   part_2
-   part_3

### Unload:

    sudo rmmod demo

------------------------------------------------------------------------

##  How Everything Works Together

  Component            Purpose
  -------------------- --------------------------------------------------
  **demo.h**           Shares declarations between all `.c` files
  **part_X.c files**   Each implements one function
  **core.c**           Calls all functions and handles module lifecycle
  **Makefile**         Combines all files into a single `.ko`

Even though there are multiple C source files, the final result is **one
kernel module**.

------------------------------------------------------------------------
