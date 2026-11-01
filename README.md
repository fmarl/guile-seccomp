# guile-seccomp

Guile bindings for [seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html)
filters through [libseccomp](https://github.com/seccomp/libseccomp).

### Example usage

This prevents new user namespaces in all threads of the process.  It also
disables `clone3`, whose flags seccomp can't inspect, so that callers fall
back to `clone`, and `keyctl`:

```scheme
(use-modules (seccomp))

(define %clone-newuser #x10000000)

(define (deny-newuser syscall)
  (seccomp-rule syscall `(errno ,EPERM)
                (seccomp-argument 0 'masked= %clone-newuser
                                  #:mask %clone-newuser)))

(seccomp-restrict!
 (list (deny-newuser 'unshare)
       (deny-newuser 'clone)
       (seccomp-rule 'clone3 `(errno ,ENOSYS))
       (seccomp-rule 'keyctl `(errno ,EPERM)))
 #:flags '(tsync))
```

### seccomp-restrict! & seccomp-exec

`seccomp-restrict!` returns `fully-enforced`, `partially-enforced` if it
skipped rules of system calls this architecture doesn't have, or
`not-enforced` if seccomp isn't available.  By default it raises an error
unless the result is `fully-enforced`. Pass `#:require` to accept less.

The filter can't be removed again.  Without the `tsync` flag, it only
applies to the calling thread and the threads and processes it starts.  It
also sets `no_new_privs`, so setuid programs started afterwards gain no
privileges.

When several rules of a system call match, it's unspecified which one wins,
so keep their conditions disjoint.  Obvious clashes, like two rules with the
same conditions but different actions, are rejected.

To run another program under a filter, call `seccomp-exec` in a child
process:

```scheme
(let ((pid (primitive-fork)))
  (if (zero? pid)
      (begin
        (false-if-exception
         (seccomp-exec (list (seccomp-rule 'ptrace `(errno ,EPERM)))
                       '("/bin/sh" "-c" "make check")))
        (primitive-_exit 127))
      (waitpid pid)))
```

`seccomp-exec` takes the same options as `seccomp-restrict!`, but never runs
the program unrestricted, not even with `#:require 'not-enforced`.  The
filter already applies to `execve`, so the rules must allow everything the
program needs to start.  If executing fails, the child is still restricted,
so it should exit rather than carry on.

## Development

```sh
guix shell -m manifest.scm -- make check
guix build -f guix.scm
```
