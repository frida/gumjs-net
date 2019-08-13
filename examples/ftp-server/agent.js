const ftpd = require('@oleavr/ftpd');

const host = '127.0.0.1';
const port = 1337;

const filesystem = {
  readdir(...args) {
    let path, options, callback;

    if (args.length === 3) {
      [path, options, callback] = args;
    } else {
      [path, callback] = args;
      options = {
        encoding: 'utf8',
      };
    }

    const files = Process.enumerateModules().map(m => m.name);

    process.nextTick(() => {
      callback(null, files);
    });
  },

  stat(path, callback) {
    const now = new Date();
    const result = {
      dev: 1,
      ino: 1,
      mode: 16877,
      nlink: 1,
      uid: 0,
      gid: 0,
      rdev: 0,
      size: 1337,
      blksize: 4096,
      blocks: 8,
      atime: now,
      mtime: now,
      ctime: now,
      birthtime: now,
      isFile() { return false; },
      isDirectory() { return true; },
      isBlockDevice() { return false; },
      isCharacterDevice() { return false; },
      isSymbolicLink() { return false; },
      isFIFO() { return false; },
      isSocket() { return false; },
    };
    process.nextTick(() => {
      callback(null, result);
    });
  },
};

const server = new ftpd.FtpServer(host, {
  getInitialCwd() {
    return '/';
  },
  getRoot() {
    return '/';
  },
});
server.on('error', error => {
  console.log('*** ERROR: ' + error.stack);
});
server.on('client:connected', connection => {
  let username = null;

  connection.on('command:user', (user, success, failure) => {
    if (user) {
      username = user;
      success();
    } else {
      failure();
    }
  });

  connection.on('command:pass', (pass, success, failure) => {
    if (pass) {
      success(username, filesystem);
    } else {
      failure();
    }
  });
});

server.debugging = 4;
server.listen(port);
console.log('Listening on port ' + port);
