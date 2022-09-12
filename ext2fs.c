/*
 * Oświadczam, że zapoznałem(-am) się z regulaminem prowadzenia zajęć
 * i jestem świadomy(-a) konsekwencji niestosowania się do podanych tam zasad.
 */
#ifdef STUDENT
/* Imię i nazwisko, numer indeksu: Artur Jankowski, 317928 */
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>

#include "ext2fs_defs.h"
#include "ext2fs.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
#undef DEBUG
#ifdef DEBUG
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...)
#endif

/* Call this function when an unfixable error has happened. */
static noreturn void panic(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  exit(EXIT_FAILURE);
}

/* Number of lists containing buffered blocks. */
#define NBUCKETS 16

/* Since majority of files in a filesystem are small, `idx` values will be
 * usually low. Since ext2fs tends to allocate blocks at the beginning of each
 * block group, `ino` values are less predictable. */
#define BUCKET(ino, idx) (((ino) + (idx)) % NBUCKETS)

/* That should give us around 64kB worth of buffers. */
#define NBLOCKS (NBUCKETS * 4)

/* Structure that is used to manage buffer of single block. */
typedef struct blk {
  TAILQ_ENTRY(blk) b_hash;
  TAILQ_ENTRY(blk) b_link;
  uint32_t b_blkaddr; /* block address on the block device */
  uint32_t b_inode;   /* i-node number of file this buffer refers to */
  uint32_t b_index;   /* block index from the beginning of file */
  uint32_t b_refcnt;  /* if zero then block can be reused */
  void *b_data;       /* raw data from this buffer */
} blk_t;

typedef TAILQ_HEAD(blk_list, blk) blk_list_t;

/* BLK_ZERO is a special value that reflect the fact that block 0 may be used to
 * represent a block filled with zeros. You must not dereference the value! */
#define BLK_ZERO ((blk_t *)-1L)

/* All memory for buffers and buffer management is allocated statically.
 * Using malloc for these would introduce unnecessary complexity. */
static alignas(BLKSIZE) char blkdata[NBLOCKS][BLKSIZE];
static blk_t blocks[NBLOCKS];
static blk_list_t buckets[NBUCKETS]; /* all blocks with valid data */
static blk_list_t lrulst;            /* free blocks with valid data */
static blk_list_t freelst;           /* free blocks that are empty */

/* File descriptor that refers to ext2 filesystem image. */
static int fd_ext2 = -1;

/* How many i-nodes fit into one block? */
#define BLK_INODES (BLKSIZE / sizeof(ext2_inode_t))

/* How many block pointers fit into one block? */
#define BLK_POINTERS (BLKSIZE / sizeof(uint32_t))

/* Properties extracted from a superblock and block group descriptors. */
static size_t inodes_per_group;      /* number of i-nodes in block group */
static size_t blocks_per_group;      /* number of blocks in block group */
static size_t group_desc_count;      /* numbre of block group descriptors */
static size_t block_count;           /* number of blocks in the filesystem */
static size_t inode_count;           /* number of i-nodes in the filesystem */
static size_t first_data_block;      /* first block managed by block bitmap */
static ext2_groupdesc_t *group_desc; /* block group descriptors in memory */

/*
 * Buffering routines.
 */

/* Opens filesystem image file and initializes block buffers. */
static int blk_init(const char *fspath) {
  if ((fd_ext2 = open(fspath, O_RDONLY)) < 0)
    return errno;

  /* Initialize list structures. */
  TAILQ_INIT(&lrulst);
  TAILQ_INIT(&freelst);
  for (int i = 0; i < NBUCKETS; i++)
    TAILQ_INIT(&buckets[i]);

  /* Initialize all blocks and put them on free list. */
  for (int i = 0; i < NBLOCKS; i++) {
    blocks[i].b_data = blkdata[i];
    TAILQ_INSERT_TAIL(&freelst, &blocks[i], b_link);
  }

  return 0;
}

/* Allocates new block buffer. */
static blk_t *blk_alloc(void) {
  blk_t *blk = NULL;

  /* Initially every empty block is on free list. */
  if (!TAILQ_EMPTY(&freelst)) {
#ifdef STUDENT
    /* OK */
    blk = TAILQ_FIRST(&freelst);
    TAILQ_REMOVE(&freelst, blk, b_link);
#endif /* !STUDENT */
    return blk;
  }

  /* Eventually free list will become exhausted.
   * Then we'll take the last recently used entry from LRU list. */
  if (!TAILQ_EMPTY(&lrulst)) {
#ifdef STUDENT
    /* OK */
    blk = TAILQ_LAST(&lrulst, blk_list); // get last
    TAILQ_REMOVE(&lrulst, blk, b_link);  // remove it

    // clear the block from associated buffer bucket
    uint32_t ino = blk->b_inode;
    uint32_t idx = blk->b_index;
    blk_list_t *bucket = &buckets[BUCKET(ino, idx)];
    TAILQ_REMOVE(bucket, blk, b_hash);
#endif /* !STUDENT */
    return blk;
  }

  /* No buffers!? Have you forgot to release some? */
  panic("Free buffers pool exhausted!");
}

/* Acquires a block buffer for file identified by `ino` i-node and block index
 * `idx`. When `ino` is zero the buffer refers to filesystem metadata (i.e.
 * superblock, block group descriptors, block & i-node bitmap, etc.) and `off`
 * offset is given from the start of block device. */
static blk_t *blk_get(uint32_t ino, uint32_t idx) {
  blk_list_t *bucket = &buckets[BUCKET(ino, idx)];
  blk_t *blk = NULL;

  /* Locate a block in the buffer and return it if found. */
#ifdef STUDENT
  /* OK */
  debug("blk_get called!\n");

  // go through blocks in the bucket
  TAILQ_FOREACH (blk, bucket, b_hash) {
    if ((blk->b_inode == ino) && blk->b_index == idx) {
      debug("blk_get found inode: (inode: %d, index: %d)\n", ino, idx);

      // if refcnt was 0 then the block is also in the lrulist
      if (blk->b_refcnt == 0) {
        TAILQ_REMOVE(&lrulst, blk, b_link);
      }
      blk->b_refcnt++;

      return blk;
    }
  }
#endif /* !STUDENT */

  long blkaddr = ext2_blkaddr_read(ino, idx);
  debug("ext2_blkaddr_read(%d, %d) -> %ld\n", ino, idx, blkaddr);
  if (blkaddr == -1)
    return NULL;
  if (blkaddr == 0)
    return BLK_ZERO;
  if (ino > 0 && !ext2_block_used(blkaddr))
    panic("Attempt to read block %d that is not in use!", blkaddr);

  blk = blk_alloc();
  blk->b_inode = ino;
  blk->b_index = idx;
  blk->b_blkaddr = blkaddr;
  blk->b_refcnt = 1;

  ssize_t nread =
    pread(fd_ext2, blk->b_data, BLKSIZE, blk->b_blkaddr * BLKSIZE);
  if (nread != BLKSIZE)
    panic("Attempt to read past the end of filesystem!");

  TAILQ_INSERT_HEAD(bucket, blk, b_hash);
  return blk;
}

/* Releases a block buffer. If reference counter hits 0 the buffer can be
 * reused to cache another block. The buffer is put at the beginning of LRU list
 * of unused blocks. */
static void blk_put(blk_t *blk) {
  if (--blk->b_refcnt > 0)
    return;

  TAILQ_INSERT_HEAD(&lrulst, blk, b_link);
}

/*
 * Ext2 filesystem routines.
 */

/* Reads block bitmap entry for `blkaddr`. Returns 0 if the block is free,
 * 1 if it's in use, and EINVAL if `blkaddr` is out of range. */
int ext2_block_used(uint32_t blkaddr) {
  if (blkaddr >= block_count)
    return EINVAL;
  int used = 0;
#ifdef STUDENT
  /* OK */
  debug("called block used with blkaddr: %d\n", blkaddr);

  // calculate block group for given address (starts from 1!)
  size_t group_id = (blkaddr - 1) / blocks_per_group;
  ext2_groupdesc_t block_gd = group_desc[group_id];

  // get block bitmap from buffer
  blk_t *blk = blk_get(0, block_gd.gd_b_bitmap);
  uint8_t *blk_bitmap = (uint8_t *)blk->b_data;

  /* "The first block of this block group is represented by bit 0 of byte 0,
   *  the second by bit 1 of byte 0. The 8th block is represented by bit 7
   *  (most significant bit) of byte 0 while the 9th block is represented by
   *  bit 0 (least significant bit) of byte 1."
   *  index inside bitmap"
   */
  size_t group_idx = (blkaddr - 1) % blocks_per_group;

  debug("block_used, id: %ld, idx: %ld\n", group_id, group_idx);
  // check bit

  used = blk_bitmap[group_idx / 8]; // byte
  used = (used >> (group_idx % 8)); // move bit rightwise
  used &= 1;                        // mask to binary result

  // return blk
  blk_put(blk);

  debug("block_used: val: %d!\n", used);
#endif /* !STUDENT */
  return used;
}

/* Reads i-node bitmap entry for `ino`. Returns 0 if the i-node is free,
 * 1 if it's in use, and EINVAL if `ino` value is out of range. */
int ext2_inode_used(uint32_t ino) {
  if (!ino || ino >= inode_count)
    return EINVAL;
  int used = 0;
#ifdef STUDENT
  /* OK */
  debug("called inode_used with inode: %d\n", ino);

  // calculate group for given inode (starts from 1!)
  size_t group_id = (ino - 1) / inodes_per_group;
  ext2_groupdesc_t block_gd = group_desc[group_id];

  // get inode bitmap from buffer
  blk_t *blk = blk_get(0, block_gd.gd_i_bitmap);
  uint8_t *i_bitmap = (uint8_t *)blk->b_data;

  // check bit
  size_t group_idx = (ino - 1) % inodes_per_group;

  debug("inode_used, id: %ld, idx: %ld\n", group_id, group_idx);
  used = i_bitmap[group_idx / 8];   // byte
  used = (used >> (group_idx % 8)); // move bit rightwise
  used &= 1;                        // mask to binary result

  // return blk
  blk_put(blk);

  debug("inode_used: val: %d\n", used);
#endif /* !STUDENT */
  return used;
}

/* Reads i-node identified by number `ino`.
 * Returns 0 on success. If i-node is not allocated returns ENOENT. */
static int ext2_inode_read(off_t ino, ext2_inode_t *inode) {
#ifdef STUDENT
  /* OK */
  debug("called inode_read read with inode: %ld\n", ino);

  int used = ext2_inode_used(ino);
  if (used == 0 || used == EINVAL) {
    debug("inode is either free or out of range\n");
    return ENOENT;
  }

  size_t group_id = (ino - 1) / inodes_per_group;
  size_t group_idx = (ino - 1) % inodes_per_group;

  // calculate offset for reading
  ext2_groupdesc_t block_gd = group_desc[group_id];
  size_t i_tables_addr = block_gd.gd_i_tables * BLKSIZE;
  size_t i_addr = i_tables_addr + group_idx * sizeof(ext2_inode_t);

  ssize_t nread = pread(fd_ext2, inode, sizeof(ext2_inode_t), i_addr);
  if (nread != sizeof(ext2_inode_t))
    panic("Inode read fail!");

  debug("finished inode_read read with inode: %ld\n", ino);
#endif /* !STUDENT */
  return 0;
}

/* Returns block pointer `blkidx` from block of `blkaddr` address. */
static uint32_t ext2_blkptr_read(uint32_t blkaddr, uint32_t blkidx) {
#ifdef STUDENT
  /* OK */
  debug("called ext2_blkptr_read with blkaddr: %d and blkidx: %d\n", blkaddr,
        blkidx);

  // blkaddr is a block holding block pointers
  blk_t *blk = blk_get(0, blkaddr); // get block

  uint32_t blkptr = ((uint32_t *)blk->b_data)[blkidx];
  blk_put(blk); // return block

  return blkptr;
#endif /* !STUDENT */
  return 0;
}

/* Translates i-node number `ino` and block index `idx` to block address.
 * Returns -1 on failure, otherwise block address. */
long ext2_blkaddr_read(uint32_t ino, uint32_t blkidx) {
  /* No translation for filesystem metadata blocks. */
  if (ino == 0)
    return blkidx;

  ext2_inode_t inode;
  if (ext2_inode_read(ino, &inode))
    return -1;

    /* Read direct pointers or pointers from indirect blocks. */
#ifdef STUDENT
  /* OK */
  debug("ext2_blkaddr_read called with ino: %d, blkidx: %d\n", ino, blkidx);

  // not indirect block
  size_t max_size = EXT2_NDADDR;
  size_t substract = 0;
  if (blkidx < EXT2_NDADDR)
    return inode.i_blocks[blkidx];

  // single indirect (blk_pointers -> how many fit in a block)
  size_t max_ptrs_n = BLK_POINTERS; // n
  max_size += BLK_POINTERS;
  substract = EXT2_NDADDR;
  uint32_t inode_single = inode.i_blocks[EXT2_NDADDR];
  if (blkidx < max_size) {
    blkidx -= substract;
    // 1st level
    return ext2_blkptr_read(inode_single, blkidx);
  }

  // double indirect
  size_t max_ptrs_sq = BLK_POINTERS * BLK_POINTERS; // n^2
  max_size += max_ptrs_sq;
  substract += max_ptrs_n;
  uint32_t inode_double = inode.i_blocks[EXT2_NDADDR + 1];
  if (blkidx < max_size) {
    blkidx -= substract;
    size_t index1 = blkidx / max_ptrs_n;
    blkidx %= max_ptrs_n;

    // 1st level
    uint32_t index1_ptr = ext2_blkptr_read(inode_double, index1);
    // 2nd level
    return ext2_blkptr_read(index1_ptr, blkidx);
  }

  // triple indirect
  max_size += max_ptrs_sq * BLK_POINTERS; // n ^ 3
  substract += max_ptrs_sq;
  uint32_t inode_triple = inode.i_blocks[EXT2_NDADDR + 2];
  if (blkidx < max_size) {
    blkidx -= substract;
    size_t index1 = blkidx / max_ptrs_sq;
    blkidx %= max_ptrs_sq;
    size_t index2 = blkidx / max_ptrs_n;
    blkidx %= max_ptrs_n;

    // 1st level
    uint32_t index1_ptr = ext2_blkptr_read(inode_triple, index1);
    // 2nd level
    uint32_t index2_ptr = ext2_blkptr_read(index1_ptr, index2);
    // 3rd level
    return ext2_blkptr_read(index2_ptr, blkidx);
  }
#endif /* !STUDENT */
  return -1;
}

/* Reads exactly `len` bytes starting from `pos` position from any file (i.e.
 * regular, directory, etc.) identified by `ino` i-node. Returns 0 on success,
 * EINVAL if `pos` and `len` would have pointed past the last block of file.
 *
 * WARNING: This function assumes that `ino` i-node pointer is valid! */
int ext2_read(uint32_t ino, void *data, size_t pos, size_t len) {
#ifdef STUDENT
  /* OK */
  debug("ext2_read called with ino: %d, pos: %ld, len: %ld!\n", ino, pos, len);

  // inode 0 is used for reading superblock
  if (ino != 0) {
    ext2_inode_t inode;
    if (ext2_inode_read(ino, &inode) != 0) {
      panic("error reading inode: %d in ext2_read", ino);
    }

    // can read last byte, but not past it
    if (pos + len > inode.i_size) {
      return EINVAL;
    }
  }

  // first block read
  size_t blk_idx = pos / BLKSIZE;
  size_t pos_off = pos % BLKSIZE; // offset inside the block

  while (len > 0) {
    blk_t *block = blk_get(ino, blk_idx);

    // how many bytes to read
    // for last block len <= BLKSIZE
    size_t remainder_bytes = min(BLKSIZE - pos_off, len);

    if (block == BLK_ZERO) {
      memset(data, 0, remainder_bytes);
    } else {
      memcpy(data, block->b_data + pos_off, remainder_bytes);
      blk_put(block);
    }

    pos_off = 0; // offset after first should be zero (aligned to BLKSIZE)
    blk_idx++;
    pos += remainder_bytes;
    data += remainder_bytes;
    len -= remainder_bytes;
  }

  debug("ext2_read success!\n");
  return 0;
#endif /* !STUDENT */
  return EINVAL;
}

/* Reads a directory entry at position stored in `off_p` from `ino` i-node that
 * is assumed to be a directory file. The entry is stored in `de` and
 * `de->de_name` must be NUL-terminated. Assumes that entry offset is 0 or was
 * set by previous call to `ext2_readdir`. Returns 1 on success, 0 if there are
 * no more entries to read. */
#define de_name_offset offsetof(ext2_dirent_t, de_name)

int ext2_readdir(uint32_t ino, uint32_t *off_p, ext2_dirent_t *de) {
#ifdef STUDENT
  /* OK */
  debug("readdir called for ino: %d! \n", ino);

  // default offset is zero
  uint32_t off;
  if (off_p == NULL)
    off = 0;
  else
    off = *off_p;

  ext2_inode_t inode;
  if (ext2_inode_read(ino, &inode) != 0) {
    panic("can't read inode: %d in readdir call", ino);
  }
  debug("readdir: inode: %d, size: %d, size-high: %d\n", ino, inode.i_size,
        inode.i_size_high);

  *off_p = off;

  // debug("de_name_offset: %ld\n", de_name_offset);
  while (true) {
    // no more entries to read
    if (inode.i_size <= *off_p) {
      return 0;
    }

    // read till name (basically 8 bytes)
    if (ext2_read(ino, de, *off_p, de_name_offset) != 0) {
      panic("can't read till name in readdir call");
    }

    // inodes with ino = 0 are marked unused -> call recursively
    if (de->de_ino == 0) {
      *off_p += de->de_reclen;
      debug("readdir: ino==0 with reclen: %d\n", de->de_reclen);
      continue;
    }

    // read only the name
    if (ext2_read(ino, de->de_name, *off_p + de_name_offset, de->de_namelen) !=
        0) {
      panic("can't read name in readdir call");
    }
    de->de_name[de->de_namelen] = '\0'; // terminating null byte
    *off_p += de->de_reclen;
    debug("readdir: sucess\n");
    return 1; // return 1 on success
  }
#endif /* !STUDENT */
  return 0;
}

/* Read the target of a symbolic link identified by `ino` i-node into buffer
 * `buf` of size `buflen`. Returns 0 on success, EINVAL if the file is not a
 * symlink or read failed. */
int ext2_readlink(uint32_t ino, char *buf, size_t buflen) {
  int error;

  ext2_inode_t inode;
  if ((error = ext2_inode_read(ino, &inode)))
    return error;

    /* Check if it's a symlink and read it. */
#ifdef STUDENT
  /* OK */

  // not a symlink
  if ((inode.i_mode & EXT2_IFLNK) == 0)
    return EINVAL;

  if (inode.i_size > buflen)
    return EINVAL;

  if (buflen <= EXT2_MAXSYMLINKLEN) { // 60? -> store inside inode
    memcpy(buf, inode.i_blocks, inode.i_size);
    buf[inode.i_size] = '\0'; // null-terminated?
  } else {
    if (ext2_read(ino, buf, 0, inode.i_size) != 0) {
      return EINVAL;
    }
    buf[inode.i_size] = '\0';
  }

  return 0;
#endif /* !STUDENT */
  return ENOTSUP;
}

/* Read metadata from file identified by `ino` i-node and convert it to
 * `struct stat`. Returns 0 on success, or error if i-node could not be read. */
int ext2_stat(uint32_t ino, struct stat *st) {
  int error;

  ext2_inode_t inode;
  if ((error = ext2_inode_read(ino, &inode)))
    return error;

    /* Convert the metadata! */
#ifdef STUDENT
  /* OK */
  debug("ext2_stat called\n");

  st->st_atime = inode.i_atime;
  st->st_blksize = BLKSIZE;
  st->st_blocks = inode.i_nblock; // TODO: nblock_high?
  st->st_ctime = inode.i_ctime;
  // st->st_dev = ?          // device
  st->st_gid = inode.i_gid;
  st->st_ino = ino; // TODO
  st->st_mode = inode.i_mode;
  st->st_mtime = inode.i_mtime;
  st->st_nlink = inode.i_nlink;
  // st->st_rdev = ?         // device number, if device
  st->st_size = inode.i_size; // TODO i_size_high?
  st->st_uid = inode.i_uid;

#endif /* !STUDENT */
  return ENOTSUP;
}

/* Reads file identified by `ino` i-node as directory and performs a lookup of
 * `name` entry. If an entry is found, its i-inode number is stored in `ino_p`
 * and its type in stored in `type_p`. On success returns 0, or EINVAL if `name`
 * is NULL or zero length, or ENOTDIR is `ino` file is not a directory, or
 * ENOENT if no entry was found. */
int ext2_lookup(uint32_t ino, const char *name, uint32_t *ino_p,
                uint8_t *type_p) {
  int error;

  if (name == NULL || !strlen(name))
    return EINVAL;

  ext2_inode_t inode;
  if ((error = ext2_inode_read(ino, &inode)))
    return error;

#ifdef STUDENT
  /* OK */
  debug("ran ext2_lookup for %d: %s", ino, name);

  // file is not a directory
  if ((inode.i_mode & EXT2_IFDIR) == 0)
    return ENOTDIR;

  ext2_dirent_t de; // current directory entry
  // offset from beginning of inode (modified by readdir calls)
  uint32_t off = 0;
  while (ext2_readdir(ino, &off, &de)) {
    debug("off: %d, ino: %d, type: %d, name-length: %d, name: %s\n", off,
          de.de_ino, de.de_type, de.de_namelen, de.de_name);

    if (strcmp(name, de.de_name) == 0) {
      debug("found matching directory entry name\n");
      if (ino_p != NULL) {
        *ino_p = de.de_ino;
      }
      if (type_p != NULL) {
        *type_p = de.de_type;
      }

      return 0;
    }
  }
  // no entry found of given name in this directory
#endif /* !STUDENT */

  return ENOENT;
}

/* Initializes ext2 filesystem stored in `fspath` file.
 * Returns 0 on success, otherwise an error. */
int ext2_mount(const char *fspath) {
  int error;

  if ((error = blk_init(fspath)))
    return error;

  /* Read superblock and verify we support filesystem's features. */
  ext2_superblock_t sb;
  ext2_read(0, &sb, EXT2_SBOFF, sizeof(ext2_superblock_t));

  debug(">>> super block\n"
        "# of inodes      : %d\n"
        "# of blocks      : %d\n"
        "block size       : %ld\n"
        "blocks per group : %d\n"
        "inodes per group : %d\n"
        "inode size       : %d\n",
        sb.sb_icount, sb.sb_bcount, 1024UL << sb.sb_log_bsize, sb.sb_bpg,
        sb.sb_ipg, sb.sb_inode_size);

  if (sb.sb_magic != EXT2_MAGIC)
    panic("'%s' cannot be identified as ext2 filesystem!", fspath);

  if (sb.sb_rev != EXT2_REV1)
    panic("Only ext2 revision 1 is supported!");

  size_t blksize = 1024UL << sb.sb_log_bsize;
  if (blksize != BLKSIZE)
    panic("ext2 filesystem with block size %ld not supported!", blksize);

  if (sb.sb_inode_size != sizeof(ext2_inode_t))
    panic("The only i-node size supported is %d!", sizeof(ext2_inode_t));

    /* Load interesting data from superblock into global variables.
     * Read group descriptor table into memory. */
#ifdef STUDENT
  /* OK */
  inodes_per_group = sb.sb_ipg;
  blocks_per_group = sb.sb_bpg;
  block_count = sb.sb_bcount;
  inode_count = sb.sb_icount;
  first_data_block = sb.sb_first_dblock;

  // "For each block group in the file system, such a group_desc is created"
  group_desc_count = 1 + (block_count - 1) / blocks_per_group;
  size_t group_desc_len = group_desc_count * sizeof(ext2_groupdesc_t);
  group_desc = malloc(group_desc_len);
  if (group_desc == NULL) {
    panic("Not enough memory available!");
  }
  int read_err = ext2_read(0, group_desc, EXT2_GDOFF, group_desc_len);
  if (read_err) {
    panic("Group descriptor read error: pos and len points past the last block "
          "of the file.");
  }

  debug("mounted successfuly!\n");
  return 0;
#endif /* !STUDENT */
  return ENOTSUP;
}
