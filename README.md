# OpenBSD Kernel Project
A university operating systems course required working with the OpenBSD kernel. A notable assignment was creating a utility which executes commands with elevated privileges. The changes were added to the OpenBSD kernel via a patch file.

## Elements of the project

### pfexec
The executable utility that executes commands with elevated privileges (as root or another user).

### pfexecd
A daemon (running as root) which determines if the user is allowed to request elevated priviledges.

### pfexecve
A new system call that requests elevated privileges from the system and then replaces the current process image with a new process image.
