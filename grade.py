#!/usr/bin/env python3

import os
import os.path
import shutil
import signal
import subprocess
from collections import namedtuple, OrderedDict
from pprint import pprint

PROG = './ext2list'
IMAGE = 'debian9-ext2'
Group = namedtuple('Group', 'b_bitmap i_bitmap i_tables nbfree nifree ndirs')


def signame(n):
    for k, v in signal.Signals.__members__.items():
        if v.value == n:
            return k


def maybe_int(s):
    try:
        return int(s)
    except ValueError:
        return s


def parse_ext2(fsimg):
    # XXX: debugfs reports indirect blocks and ext2test does not,
    # hence I cannot compare output of blocks command :(

    debugfs = subprocess.run(
            ['/sbin/debugfs', '-R', 'stats', 'debian9-ext2.img'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)

    lines = debugfs.stdout.decode('utf-8').splitlines()

    sb = dict()
    groups = []

    while lines:
        line = lines.pop(0)

        key, val = line.split(':', 1)
        key = key.strip()
        val = val.strip()

        if 'Group' in key:
            val += ', ' + lines.pop(0).strip()
            (b_bitmap, i_bitmap, i_tables, nbfree, nifree, ndirs) = \
                map(str.split, val.split(', '))
            groups.append(Group(int(b_bitmap[-1]), int(i_bitmap[-1]),
                                int(i_tables[-1]), int(nbfree[0]),
                                int(nifree[0]), int(ndirs[0])))
        else:
            sb[key] = maybe_int(val)

    return sb, groups


def check_used(sb, count_lines):
    expected_used_blocks = (sb['Block count'] - sb['Free blocks'] -
                            sb['First block'])
    expected_used_inodes = sb['Inode count'] - sb['Free inodes']

    blocks_str, inodes_str = count_lines
    used_blocks = int(blocks_str.split(':')[1])
    used_inodes = int(inodes_str.split(':')[1])

    if used_blocks != expected_used_blocks:
        raise SystemExit(f'Used blocks value is {used_blocks}, '
                         f'expected {expected_used_blocks}!')
    else:
        print(f'Used blocks: {used_blocks}')

    if used_inodes != expected_used_inodes:
        raise SystemExit(f'Used inodes value is {used_inodes}, '
                         f'expected {expected_used_inodes}!')
    else:
        print(f'Used inodes: {used_inodes}')


def build_index(lines):
    index = dict()

    for line in lines:
        od = OrderedDict([fs.split('=') for fs in line.split()])
        path = od['path']
        del od['path']
        if path in index:
            raise SystemExit(f'File "{path}" reported twice!?')
        index[path] = od

    return index


def records_match(name, got, exp):
    got_keys = set(got.keys())
    exp_keys = set(exp.keys())
    errors = []

    if got_keys ^ exp_keys:
        missing = exp_keys - got_keys
        if missing:
            for key in missing:
                errors.append(f' - missing property: \'{key}\'')

        extra = got_keys - exp_keys
        if extra:
            for key in extra:
                errors.append(f' - unexpected property: \'{key}\'')

    if any(got[k] != exp[k] for k in got_keys):
        for key in got_keys:
            if got[key] != exp[key]:
                errors.append(f' - property \'{key}\' has value \'{got[key]}\''
                              f' (expected \'{exp[key]}\')')

    if errors:
        print(f'File \'{name}\':')
        for err in errors:
            print(err)

    return not bool(errors)


def compare_list(files_lines, expected_lines):
    errors = False

    files_index = build_index(files_lines)
    expected_index = build_index(expected_lines)

    # check if student reported extra files that do not exist
    files_keys = set(files_index.keys())
    expected_keys = set(expected_index.keys())
    keys = files_keys - expected_keys
    if keys:
        for key in sorted(keys):
            print(f'File "{key}" reported,'
                  f'but it does not exists in the filesystem!')
        errors = True

    # now check index file by file and verify attributes are the same
    for name, expected in sorted(expected_index.items()):
        if name not in files_index:
            print(f'File "{name}" has not been found!')
            errors = True
            continue

        if not records_match(name, files_index[name], expected):
            errors = True

    if errors:
        raise SystemExit('Solution is incorrect!')

    print('Solution seems to be ok!')


if __name__ == '__main__':
    os.environ['PATH'] = '/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'

    if os.path.isdir('/__w'):
        os.symlink(f'/{IMAGE}.img', f'{IMAGE}.img')
        os.symlink(f'/{IMAGE}.kern.log', f'{IMAGE}.kern.log')

    sb, groups = parse_ext2(f'{IMAGE}.img')

    ext2list = subprocess.run([PROG],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              encoding='utf-8')
    if ext2list.returncode:
        print(ext2list.stdout)
        print(ext2list.stderr)

        if ext2list.returncode > 0:
            raise SystemExit(f'{PROG}: exited abnormally with code: '
                             f'{ext2list.returncode}!')
        else:
            raise SystemExit(f'{PROG}: was terminated by ' +
                             signame(-ext2list.returncode) + ' signal!')

    files = ext2list.stdout.splitlines()
    count = ext2list.stderr.splitlines()

    check_used(sb, count)

    with open(f'{IMAGE}.kern.log', 'r') as f:
        files_expected = f.read().splitlines()

    compare_list(files, files_expected)
