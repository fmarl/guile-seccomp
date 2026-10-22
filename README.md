# guile-seccomp

Guile bindings for [seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html)
filters through [libseccomp](https://github.com/seccomp/libseccomp).

```scheme
(use-modules (seccomp))

(define %clone-newuser #x10000000)

(seccomp-restrict!
 (list (seccomp-rule 'unshare `(errno ,EPERM)
                     (seccomp-argument 0 'masked= %clone-newuser
                                       #:mask %clone-newuser))
       (seccomp-rule 'clone3 `(errno ,ENOSYS))
       (seccomp-rule 'keyctl `(errno ,EPERM)))
 #:flags '(tsync))
```

`seccomp-restrict!` skips rules of system calls unknown to this architecture
and returns `fully-enforced`, `partially-enforced` or `not-enforced`.  It
raises an error instead if the result is below `#:require`,
`partially-enforced` by default.

## Development

```sh
guix shell -m manifest.scm -- make check
guix build -f guix.scm
```
