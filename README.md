# sys-tester
testing libarary made in rust relying on syscalls.

## Architecture

The crate contains the test compiler, runner, process and FD models, seccomp
installation and notifications, ptrace integration, and all other runtime
behavior. Its build script uses libseccomp to compile the descriptor-strategy
and supervision-scope policy variants into classic-BPF blobs under Cargo's
`OUT_DIR`; no generated artifacts are written into the source tree. Building
from a clean target directory therefore requires libseccomp to be installed.

The general idea is to allow specifying reads and writes that need to happen, as well as other file operations.
All code is ran in a sandbox which emulates actually writing for the most part. 

Specifiying the requirments can be done in code. and the goal is to eventually support doing it from python. with rust runing the part that wraps syscalls.


whether or not we achive all of this scope is up in the air. but this is the general idea

note that the wraping is somewhat limited because of the relativly thin VM used. seccomp does not fully allow inspecting and modifying every part of the process 

# ideas for examples

simple copy of a file
```py
from tester import File,run_simple,run_unordered

contents = tester.random_text()

input = File.open_read('input.txt')
read_task = run_simple(input,input.read(contents),input.close())

output = File.open_write('output.txt')
write_task = run_simple(output,output.write(contents),output.close())

#for some reason we want to force input.txt to be opened first
input.before(output)

extra = tester.allow_read(".config")#opening for read and reading these is now allowed but not required

task = run_unordered(read_task,write_task,extra)

task.test()
```

echo server
```py
def make_echo_socket_task():
	s = tester.any_accept()
	contents = tester.random_text()
	echo = tester.unordered_task(s.read(contents).random_gaps(),s.write(contents))
	return tester.run_simple(s,echo,s.close())

#now run 100 echos async
run_unordered([make_echo_socket_task() for _ in range(100)])
```

handeling fails
```py
output = File.open_write('output.txt')
contents = random_text()

first_write = output.partial_write(contents,7)
second_write = first_write.try_finish_fail(error=NO_SPACE)

run_simple(output,
	first_write,second_write,
	output.truncate(0)
	output.delete()
	output.close()
)
```
# Advantages
this aproch lets you have large autogenrated tests. We can also feasibly test for race coditions across process more effectively. Since we can enforce Syscall order artificially in order to test this.

the tested program is also strongly sandboxed. with some options o
