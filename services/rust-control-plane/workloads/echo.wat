;; Approved workload: echo.
;;
;; Reads up to 4096 bytes of standard input and writes exactly those bytes to
;; standard output. No filesystem, clock or network imports: the only host
;; functions visible to this module are the three below.
(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))

  ;; One page: 64 KiB. Input lives at 0, the iovec at 8192, result slots after it.
  (memory (export "memory") 1)

  (func (export "_start")
    ;; iovec = { base: 0, len: 4096 }
    (i32.store (i32.const 8192) (i32.const 0))
    (i32.store (i32.const 8196) (i32.const 4096))

    ;; fd_read(stdin, iovec, 1, &nread)
    (drop (call $fd_read
      (i32.const 0)
      (i32.const 8192)
      (i32.const 1)
      (i32.const 8200)))

    ;; Shrink the iovec to what was actually read.
    (i32.store (i32.const 8196) (i32.load (i32.const 8200)))

    ;; fd_write(stdout, iovec, 1, &nwritten)
    (drop (call $fd_write
      (i32.const 1)
      (i32.const 8192)
      (i32.const 1)
      (i32.const 8204)))

    (call $proc_exit (i32.const 0))
  )
)
