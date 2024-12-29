from fuse import FUSE, FuseOSError, Operations
from time import time
from stat import S_IFDIR, S_IFREG, S_IFLNK      #S_IFDIR: directory, S_IFREG: regular file, S_IFLNK: symbolic link
from errno import ENOENT, EEXIST
from collections import defaultdict
from sys import argv
from encrypt import AESCipher

class SimpleFS(Operations):
    def __init__(self):
        self.metadata:dict[str, bytes] = {}
        self.data = defaultdict(bytes)      #if the index reqired is not exist in dict, then print the null value
        self.keys = defaultdict(bytes)
        self.fd = 0                         #file descriptor
        now = time()
        self.metadata['/'] = dict(st_mode=(S_IFDIR | 0o755), st_nlink=2, st_ctime=now, st_mtime=now, st_atime=now) 
        #st_ctime: creation time, st_mtime: modification time, st_atime: access time
        '''
        print(bin(self.metadata['/'][str('st_mode')]) , bin(S_IFDIR))
        print()
        '''

#create, write and remove file
    def create(self, path, mode):
        print('create', path)
        self.metadata[path] = dict(st_mode=(S_IFREG | mode), st_nlink=1, st_size=0, st_ctime=time(), st_mtime=time(), st_atime=time())
        self.fd += 1
        self.keys[path] = AESCipher.add_key()
        print(self.data[path])
        return self.fd

    def read(self, path, size, offset, fh):
        target = AESCipher.decrypt(self.data[path], self.keys[path]) #decrypt the data
        return target[offset:offset + size]        #catch the index of path and read the data from offset to size

    def write(self, path, buf, offset, fh):
        if self.data[path] != b'':
            target = AESCipher.decrypt(self.data[path], self.keys[path]) #decrypt the data
        else:
            target = b''
        print(target)
        target = (
            # make sure the data gets inserted at the right offset
            target[:offset].ljust(offset, '\x00'.encode('ascii'))
            + buf
            # and only overwrites the bytes that data is replacing
            + target[offset + len(buf):])
            #insert the data in buffer from offset to offset+len
        self.metadata[path]['st_size'] = len(target) #update the size of the file
        self.metadata[path]['st_mtime'] = time()              #update the modification time
        self.data[path] = AESCipher.encrypt(target, self.keys[path]) #encrypt the data
        return len(buf)

    def open(self, path, flags):
        print('open', path, flags)
        self.fd += 1
        self.metadata[path]['st_atime'] = time()
        return self.fd

    def release(self, path, fd):
        print('release', path, fd)
        return 0

    def truncate(self, path, length, fd=None):
        print('truncate', path, length)
        if self.data[path] != b'':
            target = AESCipher.decrypt(self.data[path], self.keys[path]) #decrypt the data
        else:
            target = b''
        target = target[:length] #divide the path's size to length
        self.metadata[path]['st_size'] = length    #specify the size of the file
        self.metadata[path]['st_mtime'] = time()


#create and remove directory
    def mkdir(self, path, mode):
        self.metadata[path] = dict(
            st_mode=(S_IFDIR | mode),
            st_nlink=2,
            st_size=0,
            st_ctime=time(),
            st_mtime=time(),
            st_atime=time())
        self.metadata['/']['st_nlink'] += 1

    def rmdir(self, path):
        # with multiple level support, need to raise ENOTEMPTY if contains any files
        self.metadata.pop(path)
        self.metadata['/']['st_nlink'] -= 1

#list directory contents
    def readdir(self, path, fh):
        return ['.', '..'] + [x[1:] for x in self.metadata if x != '/']

#file and directory attributes
    def getattr(self, path, fh=None):
        print('getattr', path)
        if path not in self.metadata:
            print('raise FuseOSError(ENOENT)')
            raise FuseOSError(ENOENT)
        return self.metadata[path]


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('mount')
    args = parser.parse_args()

    fuse = FUSE(SimpleFS(), args.mount, foreground=True)