import {
  TCP,
  Pipe,
  TCPConnectWrap,
  PipeConnectWrap,
  ShutdownWrap,
  WriteWrap
} from './lib/adapter.js';

import assert from 'assert';
import { Buffer } from 'buffer';
import EventEmitter from 'events';
import process from 'process';
import stream from 'stream';
import timers from 'timers';
import util from 'util';

const FridaSocket = global.Socket;

export default {
  createServer,
  createConnection,
  connect: createConnection,
  _normalizeArgs: normalizeArgs,
  Socket,
  Stream: Socket,
  Server,
  isIP,
  isIPv4,
  isIPv6,
  _setSimultaneousAccepts,
};

export {
  createServer,
  createConnection,
  createConnection as connect,
  normalizeArgs as _normalizeArgs,
  Socket,
  Socket as Stream,
  Server,
  isIP,
  isIPv4,
  isIPv6,
  _setSimultaneousAccepts,
};

function noop() {}

function createHandle(fd) {
  var type = FridaSocket.type(fd);
  if (type === 'unix:stream') return new Pipe();
  if (type === 'tcp' || type === 'tcp6') return new TCP();
  throw new TypeError('Unsupported fd type: ' + type);
}


function isPipeName(s) {
  return typeof s === 'string' && toNumber(s) === false;
}

function createServer(options, connectionListener) {
  return new Server(options, connectionListener);
}


// Target API:
//
// var s = net.connect({port: 80, host: 'google.com'}, function() {
//   ...
// });
//
// There are various forms:
//
// connect(options, [cb])
// connect(port, [host], [cb])
// connect(path, [cb]);
//
function createConnection() {
  var args = new Array(arguments.length);
  for (var i = 0; i < arguments.length; i++)
    args[i] = arguments[i];
  args = normalizeArgs(args);
  var s = new Socket(args[0]);

  if (args[0].timeout) {
    s.setTimeout(args[0].timeout);
  }

  return Socket.prototype.connect.apply(s, args);
}

// Returns an array [options, cb], where cb can be null.
// It is the same as the argument of Socket.prototype.connect().
// This is used by Server.prototype.listen() and Socket.prototype.connect().
function normalizeArgs(args) {
  var options = {};

  if (args.length === 0) {
    return [options];
  } else if (args[0] !== null && typeof args[0] === 'object') {
    // connect(options, [cb])
    options = args[0];
  } else if (isPipeName(args[0])) {
    // connect(path, [cb]);
    options.path = args[0];
  } else {
    // connect(port, [host], [cb])
    options.port = args[0];
    if (args.length > 1 && typeof args[1] === 'string') {
      options.host = args[1];
    }
  }

  var cb = args[args.length - 1];
  if (typeof cb !== 'function')
    cb = null;
  return [options, cb];
}


// called when creating new Socket, or when re-using a closed Socket
function initSocketHandle(self) {
  self.destroyed = false;
  self._bytesDispatched = 0;
  self._sockname = null;

  // Handle creation may be deferred to bind() or connect() time.
  if (self._handle) {
    self._handle.owner = self;
    self._handle.onread = onread;

    // If handle doesn't support writev - neither do we
    if (!self._handle.writev)
      self._writev = null;
  }
}


const BYTES_READ = Symbol('bytesRead');


function Socket(options) {
  if (!(this instanceof Socket)) return new Socket(options);

  this.connecting = false;
  this._hadError = false;
  this._handle = null;
  this._parent = null;
  this._host = null;

  if (typeof options === 'number')
    options = { fd: options }; // Legacy interface.
  else if (options === undefined)
    options = {};

  stream.Duplex.call(this, options);

  if (options.handle) {
    this._handle = options.handle; // private
  } else if (options.fd !== undefined) {
    this._handle = createHandle(options.fd);
    this._handle.open(options.fd);
    if ((options.fd == 1 || options.fd == 2) &&
        (this._handle instanceof Pipe) &&
        process.platform === 'win32') {
      // Make stdout and stderr blocking on Windows
      var err = this._handle.setBlocking(true);
      if (err)
        throw errnoException(err, 'setBlocking');
    }
    this.readable = options.readable !== false;
    this.writable = options.writable !== false;
  } else {
    // these will be set once there is a connection
    this.readable = this.writable = false;
  }

  // shut down the socket when we're finished with it.
  this.on('finish', onSocketFinish);
  this.on('_socketEnd', onSocketEnd);

  initSocketHandle(this);

  this._pendingData = null;
  this._pendingEncoding = '';

  // default to *not* allowing half open sockets
  this.allowHalfOpen = options && options.allowHalfOpen || false;

  // if we have a handle, then start the flow of data into the
  // buffer.  if not, then this will happen when we connect
  if (this._handle && options.readable !== false) {
    if (options.pauseOnCreate) {
      // stop the handle from reading and pause the stream
      this._handle.reading = false;
      this._handle.readStop();
      this._readableState.flowing = false;
    } else {
      this.read(0);
    }
  }

  // Reserve properties
  this.server = null;
  this._server = null;

  // Used after `.destroy()`
  this[BYTES_READ] = 0;
}
util.inherits(Socket, stream.Duplex);

Socket.prototype._unrefTimer = function unrefTimer() {
  for (var s = this; s !== null; s = s._parent)
    timers._unrefActive(s);
};

// the user has called .end(), and all the bytes have been
// sent out to the other side.
// If allowHalfOpen is false, or if the readable side has
// ended already, then destroy.
// If allowHalfOpen is true, then we need to do a shutdown,
// so that only the writable side will be cleaned up.
function onSocketFinish() {
  // If still connecting - defer handling 'finish' until 'connect' will happen
  if (this.connecting) {
    return this.once('connect', onSocketFinish);
  }

  if (!this.readable || this._readableState.ended) {
    return this.destroy();
  }

  // otherwise, just shutdown, or destroy() if not possible
  if (!this._handle || !this._handle.shutdown)
    return this.destroy();

  var req = new ShutdownWrap();
  req.oncomplete = afterShutdown;
  req.handle = this._handle;
  var err = this._handle.shutdown(req);

  if (err)
    return this._destroy(errnoException(err, 'shutdown'));
}


function afterShutdown(error, handle, req) {
  var self = handle.owner;

  // callback may come after call to destroy.
  if (self.destroyed)
    return;

  if (self._readableState.ended) {
    self.destroy();
  } else {
    self.once('_socketEnd', self.destroy);
  }
}

// the EOF has been received, and no more bytes are coming.
// if the writable side has ended already, then clean everything
// up.
function onSocketEnd() {
  // XXX Should not have to do as much crap in this function.
  // ended should already be true, since this is called *after*
  // the EOF errno and onread has eof'ed
  this._readableState.ended = true;
  if (this._readableState.endEmitted) {
    this.readable = false;
    maybeDestroy(this);
  } else {
    this.once('end', function() {
      this.readable = false;
      maybeDestroy(this);
    });
    this.read(0);
  }

  if (!this.allowHalfOpen) {
    this.write = writeAfterFIN;
    this.destroySoon();
  }
}

// Provide a better error message when we call end() as a result
// of the other side sending a FIN.  The standard 'write after end'
// is overly vague, and makes it seem like the user's code is to blame.
function writeAfterFIN(chunk, encoding, cb) {
  if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  var er = new Error('This socket has been ended by the other party');
  er.code = 'EPIPE';
  // TODO: defer error events consistently everywhere, not just the cb
  this.emit('error', er);
  if (typeof cb === 'function') {
    process.nextTick(cb, er);
  }
}

Socket.prototype.read = function(n) {
  if (n === 0)
    return stream.Readable.prototype.read.call(this, n);

  this.read = stream.Readable.prototype.read;
  this._consuming = true;
  return this.read(n);
};


Socket.prototype.listen = function() {
  this.on('connection', arguments[0]);
  listen(this, null, null, null);
};


Socket.prototype.setTimeout = function(msecs, callback) {
  if (msecs === 0) {
    timers.unenroll(this);
    if (callback) {
      this.removeListener('timeout', callback);
    }
  } else {
    timers.enroll(this, msecs);
    timers._unrefActive(this);
    if (callback) {
      this.once('timeout', callback);
    }
  }
  return this;
};


Socket.prototype._onTimeout = function() {
  this.emit('timeout');
};


Socket.prototype.setNoDelay = function(enable) {
  if (!this._handle) {
    this.once('connect',
              enable ? this.setNoDelay : () => this.setNoDelay(enable));
    return this;
  }

  // backwards compatibility: assume true when `enable` is omitted
  if (this._handle.setNoDelay)
    this._handle.setNoDelay(enable === undefined ? true : !!enable);

  return this;
};


Socket.prototype.setKeepAlive = function(setting, msecs) {
  if (!this._handle) {
    this.once('connect', () => this.setKeepAlive(setting, msecs));
    return this;
  }

  if (this._handle.setKeepAlive)
    this._handle.setKeepAlive(setting, ~~(msecs / 1000));

  return this;
};


Socket.prototype.address = function() {
  return this._getsockname();
};


Object.defineProperty(Socket.prototype, '_connecting', {
  get: function() {
    return this.connecting;
  }
});


Object.defineProperty(Socket.prototype, 'readyState', {
  get: function() {
    if (this.connecting) {
      return 'opening';
    } else if (this.readable && this.writable) {
      return 'open';
    } else if (this.readable && !this.writable) {
      return 'readOnly';
    } else if (!this.readable && this.writable) {
      return 'writeOnly';
    } else {
      return 'closed';
    }
  }
});


Object.defineProperty(Socket.prototype, 'bufferSize', {
  get: function() {
    if (this._handle) {
      return this._handle.writeQueueSize + this._writableState.length;
    }
  }
});


// Just call handle.readStart until we have enough in the buffer
Socket.prototype._read = function(n) {
  if (this.connecting || !this._handle) {
    this.once('connect', () => this._read(n));
  } else if (!this._handle.reading) {
    // not already reading, start the flow
    this._handle.reading = true;
    var err = this._handle.readStart();
    if (err)
      this._destroy(errnoException(err, 'read'));
  }
};


Socket.prototype.end = function(data, encoding) {
  stream.Duplex.prototype.end.call(this, data, encoding);
  this.writable = false;

  // just in case we're waiting for an EOF.
  if (this.readable && !this._readableState.endEmitted)
    this.read(0);
  else
    maybeDestroy(this);
};


// Call whenever we set writable=false or readable=false
function maybeDestroy(socket) {
  if (!socket.readable &&
      !socket.writable &&
      !socket.destroyed &&
      !socket.connecting &&
      !socket._writableState.length) {
    socket.destroy();
  }
}


Socket.prototype.destroySoon = function() {
  if (this.writable)
    this.end();

  if (this._writableState.finished)
    this.destroy();
  else
    this.once('finish', this.destroy);
};


Socket.prototype._destroy = function(exception, cb) {
  function fireErrorCallbacks(self) {
    if (cb) cb(exception);
    if (exception && !self._writableState.errorEmitted) {
      process.nextTick(emitErrorNT, self, exception);
      self._writableState.errorEmitted = true;
    }
  }

  if (this.destroyed) {
    fireErrorCallbacks(this);
    return;
  }

  this.connecting = false;

  this.readable = this.writable = false;

  for (var s = this; s !== null; s = s._parent)
    timers.unenroll(s);

  if (this._handle) {
    var isException = exception ? true : false;
    // `bytesRead` should be accessible after `.destroy()`
    this[BYTES_READ] = this._handle.bytesRead;

    this._handle.close(() => {
      this.emit('close', isException);
    });
    this._handle.onread = noop;
    this._handle = null;
    this._sockname = null;
  }

  // we set destroyed to true before firing error callbacks in order
  // to make it re-entrance safe in case Socket.prototype.destroy()
  // is called within callbacks
  this.destroyed = true;
  fireErrorCallbacks(this);

  if (this._server) {
    this._server._connections--;
    if (this._server._emitCloseIfDrained) {
      this._server._emitCloseIfDrained();
    }
  }
};


Socket.prototype.destroy = function(exception) {
  this._destroy(exception);
};


// This function is called whenever the handle gets a
// buffer, or when there's an error reading.
function onread(error, nread, buffer) {
  var handle = this;
  var self = handle.owner;
  assert(handle === self._handle, 'handle != self._handle');

  self._unrefTimer();

  if (nread > 0) {
    // read success.
    // In theory (and in practice) calling readStop right now
    // will prevent this from being called again until _read() gets
    // called again.

    // Optimization: emit the original buffer with end points
    var ret = self.push(buffer);

    if (handle.reading && !ret) {
      handle.reading = false;
      var err = handle.readStop();
      if (err)
        self._destroy(errnoException(err, 'read'));
    }
    return;
  }

  if (error !== null) {
    return self._destroy(errnoException(error, 'read'));
  }

  if (self._readableState.length === 0) {
    self.readable = false;
    maybeDestroy(self);
  }

  // push a null to signal the end of data.
  self.push(null);

  // internal end event so that we know that the actual socket
  // is no longer readable, and we can start the shutdown
  // procedure. No need to wait for all the data to be consumed.
  self.emit('_socketEnd');
}


Socket.prototype._getpeername = function() {
  if (!this._peername) {
    if (!this._handle || !this._handle.getpeername) {
      return {};
    }
    var out = {};
    var err = this._handle.getpeername(out);
    if (err) return {};  // FIXME(bnoordhuis) Throw?
    this._peername = out;
  }
  return this._peername;
};

function protoGetter(name, callback) {
  Object.defineProperty(Socket.prototype, name, {
    configurable: false,
    enumerable: true,
    get: callback
  });
}

protoGetter('bytesRead', function bytesRead() {
  return this._handle ? this._handle.bytesRead : this[BYTES_READ];
});

protoGetter('remoteAddress', function remoteAddress() {
  return this._getpeername().address;
});

protoGetter('remoteFamily', function remoteFamily() {
  return this._getpeername().family;
});

protoGetter('remotePort', function remotePort() {
  return this._getpeername().port;
});


Socket.prototype._getsockname = function() {
  if (!this._handle || !this._handle.getsockname) {
    return {};
  }
  if (!this._sockname) {
    var out = {};
    var err = this._handle.getsockname(out);
    if (err) return {};  // FIXME(bnoordhuis) Throw?
    this._sockname = out;
  }
  return this._sockname;
};


protoGetter('localAddress', function localAddress() {
  return this._getsockname().address;
});


protoGetter('localPort', function localPort() {
  return this._getsockname().port;
});


Socket.prototype.write = function(chunk, encoding, cb) {
  if (typeof chunk !== 'string' && !(chunk instanceof Buffer)) {
    throw new TypeError(
      'Invalid data, chunk must be a string or buffer, not ' + typeof chunk);
  }
  return stream.Duplex.prototype.write.apply(this, arguments);
};


Socket.prototype._writeGeneric = function(writev, data, encoding, cb) {
  // If we are still connecting, then buffer this for later.
  // The Writable logic will buffer up any more writes while
  // waiting for this one to be done.
  if (this.connecting) {
    this._pendingData = data;
    this._pendingEncoding = encoding;
    this.once('connect', function() {
      this._writeGeneric(writev, data, encoding, cb);
    });
    return;
  }
  this._pendingData = null;
  this._pendingEncoding = '';

  this._unrefTimer();

  if (!this._handle) {
    this._destroy(new Error('This socket is closed'), cb);
    return false;
  }

  var req = new WriteWrap();
  req.handle = this._handle;
  req.oncomplete = afterWrite;
  req.cb = cb;
  var err;

  if (writev) {
    var chunks = new Array(data.length << 1);
    for (var i = 0; i < data.length; i++) {
      var entry = data[i];
      chunks[i * 2] = entry.chunk;
      chunks[i * 2 + 1] = entry.encoding;
    }
    err = this._handle.writev(req, chunks);

    // Retain chunks
    if (!err) req._chunks = chunks;
  } else {
    var enc;
    if (data instanceof Buffer) {
      enc = 'buffer';
    } else {
      enc = encoding;
    }
    err = createWriteReq(req, this._handle, data, enc);
  }

  if (err)
    return this._destroy(errnoException(err, 'write', req.error), cb);

  this._bytesDispatched += req.bytes;
};


Socket.prototype._writev = function(chunks, cb) {
  this._writeGeneric(true, chunks, '', cb);
};


Socket.prototype._write = function(data, encoding, cb) {
  this._writeGeneric(false, data, encoding, cb);
};

function createWriteReq(req, handle, data, encoding) {
  switch (encoding) {
    case 'latin1':
    case 'binary':
      return handle.writeLatin1String(req, data);

    case 'buffer':
      return handle.writeBuffer(req, data);

    case 'utf8':
    case 'utf-8':
      return handle.writeUtf8String(req, data);

    case 'ascii':
      return handle.writeAsciiString(req, data);

    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return handle.writeUcs2String(req, data);

    default:
      return handle.writeBuffer(req, Buffer.from(data, encoding));
  }
}


protoGetter('bytesWritten', function bytesWritten() {
  var bytes = this._bytesDispatched;
  const state = this._writableState;
  const data = this._pendingData;
  const encoding = this._pendingEncoding;

  if (!state)
    return undefined;

  state.getBuffer().forEach(function(el) {
    if (el.chunk instanceof Buffer)
      bytes += el.chunk.length;
    else
      bytes += Buffer.byteLength(el.chunk, el.encoding);
  });

  if (data) {
    if (data instanceof Buffer)
      bytes += data.length;
    else
      bytes += Buffer.byteLength(data, encoding);
  }

  return bytes;
});


function afterWrite(error, handle, req) {
  var self = handle.owner;

  // callback may come after call to destroy.
  if (self.destroyed) {
    return;
  }

  if (error !== null) {
    var ex = errnoException(error, 'write', req.error);
    self._destroy(ex, req.cb);
    return;
  }

  self._unrefTimer();

  if (req.cb)
    req.cb.call(self);
}


function connect(self, address, port, addressType, localAddress, localPort) {
  // TODO return promise from Socket.prototype.connect which
  // wraps _connectReq.

  assert.ok(self.connecting);

  var err;

  if (localAddress || localPort) {
    throw new Error('Local address/port is not yet supported');
  }

  if (addressType === 6 || addressType === 4) {
    const req = new TCPConnectWrap();
    req.oncomplete = afterConnect;
    req.address = address;
    req.port = port;
    req.localAddress = localAddress;
    req.localPort = localPort;

    err = self._handle.connect(req, address, port);
  } else {
    const req = new PipeConnectWrap();
    req.address = address;
    req.oncomplete = afterConnect;
    err = self._handle.connect(req, address, afterConnect);
  }

  if (err) {
    var sockname = self._getsockname();
    var details;

    if (sockname) {
      details = sockname.address + ':' + sockname.port;
    }

    const ex = exceptionWithHostPort(err, 'connect', address, port, details);
    self._destroy(ex);
  }
}


Socket.prototype.connect = function(options, cb) {
  if (this.write !== Socket.prototype.write)
    this.write = Socket.prototype.write;

  if (options === null || typeof options !== 'object') {
    // Old API:
    // connect(port, [host], [cb])
    // connect(path, [cb]);
    var args = new Array(arguments.length);
    for (var i = 0; i < arguments.length; i++)
      args[i] = arguments[i];
    args = normalizeArgs(args);
    return Socket.prototype.connect.apply(this, args);
  }

  if (this.destroyed) {
    this._readableState.reading = false;
    this._readableState.ended = false;
    this._readableState.endEmitted = false;
    this._writableState.ended = false;
    this._writableState.ending = false;
    this._writableState.finished = false;
    this._writableState.errorEmitted = false;
    this.destroyed = false;
    this._handle = null;
    this._peername = null;
    this._sockname = null;
  }

  var pipe = !!options.path;

  if (!this._handle) {
    this._handle = pipe ? new Pipe() : new TCP();
    initSocketHandle(this);
  }

  if (typeof cb === 'function') {
    this.once('connect', cb);
  }

  this._unrefTimer();

  this.connecting = true;
  this.writable = true;

  if (pipe) {
    connect(this, options.path);
  } else {
    lookupAndConnect(this, options);
  }
  return this;
};


function lookupAndConnect(self, options) {
  var host = options.host || 'localhost';
  var port = options.port;
  var localAddress = options.localAddress;
  var localPort = options.localPort;

  if (localAddress && !isIP(localAddress))
    throw new TypeError('"localAddress" option must be a valid IP: ' +
                        localAddress);

  if (localPort && typeof localPort !== 'number')
    throw new TypeError('"localPort" option should be a number: ' + localPort);

  if (typeof port !== 'undefined') {
    if (typeof port !== 'number' && typeof port !== 'string')
      throw new TypeError('"port" option should be a number or string: ' +
                          port);
    if (!isLegalPort(port))
      throw new RangeError('"port" option should be >= 0 and < 65536: ' + port);
  }
  port |= 0;

  if (options.lookup)
    throw new TypeError('"lookup" option is not yet supported');

  var addressType = isIP(host);
  if (addressType === 0)
    addressType = 4;

  process.nextTick(function() {
    if (self.connecting)
      connect(self, host, port, addressType, localAddress, localPort);
  });
}


Socket.prototype.ref = function() {
  if (!this._handle) {
    this.once('connect', this.ref);
    return this;
  }

  this._handle.ref();

  return this;
};


Socket.prototype.unref = function() {
  if (!this._handle) {
    this.once('connect', this.unref);
    return this;
  }

  this._handle.unref();

  return this;
};


function afterConnect(error, handle, req, readable, writable) {
  var self = handle.owner;

  // callback may come after call to destroy
  if (self.destroyed) {
    return;
  }

  // Update handle if it was wrapped
  // TODO(indutny): assert that the handle is actually an ancestor of old one
  handle = self._handle;

  assert.ok(self.connecting);
  self.connecting = false;
  self._sockname = null;

  if (error === null) {
    self.readable = readable;
    self.writable = writable;
    self._unrefTimer();

    self.emit('connect');

    // start the first read, or get an immediate EOF.
    // this doesn't actually consume any bytes, because len=0.
    if (readable && !self.isPaused())
      self.read(0);

  } else {
    self.connecting = false;
    var details;
    if (req.localAddress && req.localPort) {
      details = req.localAddress + ':' + req.localPort;
    }
    var ex = exceptionWithHostPort(error,
                                   'connect',
                                   req.address,
                                   req.port,
                                   details);
    if (details) {
      ex.localAddress = req.localAddress;
      ex.localPort = req.localPort;
    }
    self._destroy(ex);
  }
}


function Server(options, connectionListener) {
  if (!(this instanceof Server))
    return new Server(options, connectionListener);

  EventEmitter.call(this);

  if (typeof options === 'function') {
    connectionListener = options;
    options = {};
    this.on('connection', connectionListener);
  } else if (options == null || typeof options === 'object') {
    options = options || {};

    if (typeof connectionListener === 'function') {
      this.on('connection', connectionListener);
    }
  } else {
    throw new TypeError('options must be an object');
  }

  this._connections = 0;

  Object.defineProperty(this, 'connections', {
    get: () => {

      if (this._usingSlaves) {
        return null;
      }
      return this._connections;
    },
    set: (val) => {
      return (this._connections = val);
    },
    configurable: true, enumerable: false
  });

  this._handle = null;
  this._usingSlaves = false;
  this._slaves = [];
  this._unref = false;

  this.allowHalfOpen = options.allowHalfOpen || false;
  this.pauseOnConnect = !!options.pauseOnConnect;
}
util.inherits(Server, EventEmitter);


function toNumber(x) { return (x = Number(x)) >= 0 ? x : false; }

Server.prototype._listen2 = function(address, port, addressType, backlog, fd) {
  // If there is not yet a handle, we need to create one and bind.
  // In the case of a server sent via IPC, we don't need to do this.
  if (!this._handle) {
    let handle;
    if (typeof fd === 'number' && fd >= 0) {
      try {
        handle = createHandle(fd);
      } catch (e) {
        // Not a fd we can listen on.  This will trigger an error.
        const error = exceptionWithHostPort(e, 'listen', address, port);
        process.nextTick(emitErrorNT, this, error);
        return;
      }
      handle.open(fd);
      handle.readable = true;
      handle.writable = true;
      assert(!address && !port);
    } else if (port === -1 && addressType === -1) {
      handle = new Pipe();
    } else {
      handle = new TCP();
    }
    this._handle = handle;
  }

  this._handle.onconnection = onconnection;
  this._handle.owner = this;

  // Use a backlog of 512 entries. We pass 511 to the listen() call because
  // the kernel does: backlogsize = roundup_pow_of_two(backlogsize + 1);
  // which will thus give us a backlog of 512 entries.
  this._handle.listen(address, port, backlog || 511, err => {
    if (err) {
      var ex = exceptionWithHostPort(err, 'listen', address, port);
      this._handle.close();
      this._handle = null;
      process.nextTick(emitErrorNT, this, ex);
      return;
    }

    // generate connection key, this should be unique to the connection
    this._connectionKey = addressType + ':' + address + ':' + port;

    // unref the handle if the server was unref'ed prior to listening
    if (this._unref)
      this.unref();

    process.nextTick(emitListeningNT, this);
  });
};


function emitErrorNT(self, err) {
  self.emit('error', err);
}


function emitListeningNT(self) {
  // ensure handle hasn't closed
  if (self._handle)
    self.emit('listening');
}


function listen(self, address, port, addressType, backlog, fd, exclusive) {
  self._listen2(address, port, addressType, backlog, fd);
}


Server.prototype.listen = function() {
  var args = new Array(arguments.length);
  for (var i = 0; i < arguments.length; i++)
    args[i] = arguments[i];
  var [options, cb] = normalizeArgs(args);

  if (typeof cb === 'function') {
    this.once('listening', cb);
  }

  if (args.length === 0 || typeof args[0] === 'function') {
    // Bind to a random port.
    options.port = 0;
  }

  // The third optional argument is the backlog size.
  // When the ip is omitted it can be the second argument.
  var backlog = toNumber(args.length > 1 && args[1]) ||
                toNumber(args.length > 2 && args[2]);

  options = options._handle || options.handle || options;

  if (options instanceof TCP) {
    this._handle = options;
    listen(this, null, -1, -1, backlog);
  } else if (typeof options.fd === 'number' && options.fd >= 0) {
    listen(this, null, null, null, backlog, options.fd);
  } else {
    backlog = options.backlog || backlog;

    if (typeof options.port === 'number' || typeof options.port === 'string' ||
        (typeof options.port === 'undefined' && 'port' in options)) {
      // Undefined is interpreted as zero (random port) for consistency
      // with net.connect().
      assertPort(options.port);
      listen(this, options.host ?? null, options.port ?? 0, 4, backlog,
             undefined, options.exclusive);
    } else if (options.path && isPipeName(options.path)) {
      // UNIX socket or Windows pipe.
      const pipeName = this._pipeName = options.path;
      listen(this, pipeName, -1, -1, backlog, undefined, options.exclusive);
    } else {
      throw new Error('Invalid listen argument: ' + options);
    }
  }

  return this;
};

Object.defineProperty(Server.prototype, 'listening', {
  get: function() {
    return !!(this._handle && this._connectionKey);
  },
  configurable: true,
  enumerable: true
});

Server.prototype.address = function() {
  if (this._handle && this._handle.getsockname) {
    var out = {};
    this._handle.getsockname(out);
    // TODO(bnoordhuis) Check err and throw?
    return out;
  } else if (this._pipeName) {
    return this._pipeName;
  } else {
    return null;
  }
};

function onconnection(err, clientHandle) {
  var handle = this;
  var self = handle.owner;

  if (err) {
    self.emit('error', errnoException(err, 'accept'));
    return;
  }

  if (self.maxConnections && self._connections >= self.maxConnections) {
    clientHandle.close();
    return;
  }

  var socket = new Socket({
    handle: clientHandle,
    allowHalfOpen: self.allowHalfOpen,
    pauseOnCreate: self.pauseOnConnect
  });
  socket.readable = socket.writable = true;


  self._connections++;
  socket.server = self;
  socket._server = self;

  self.emit('connection', socket);
}


Server.prototype.getConnections = function(cb) {
  function end(err, connections) {
    process.nextTick(cb, err, connections);
  }

  if (!this._usingSlaves) {
    return end(null, this._connections);
  }

  // Poll slaves
  var left = this._slaves.length;
  var total = this._connections;

  function oncount(err, count) {
    if (err) {
      left = -1;
      return end(err);
    }

    total += count;
    if (--left === 0) return end(null, total);
  }

  this._slaves.forEach(function(slave) {
    slave.getConnections(oncount);
  });
};


Server.prototype.close = function(cb) {
  function onSlaveClose() {
    if (--left !== 0) return;

    self._connections = 0;
    self._emitCloseIfDrained();
  }

  if (typeof cb === 'function') {
    if (!this._handle) {
      this.once('close', function() {
        cb(new Error('Not running'));
      });
    } else {
      this.once('close', cb);
    }
  }

  if (this._handle) {
    this._handle.close();
    this._handle = null;
  }

  if (this._usingSlaves) {
    var self = this;
    var left = this._slaves.length;

    // Increment connections to be sure that, even if all sockets will be closed
    // during polling of slaves, `close` event will be emitted only once.
    this._connections++;

    // Poll slaves
    this._slaves.forEach(function(slave) {
      slave.close(onSlaveClose);
    });
  } else {
    this._emitCloseIfDrained();
  }

  return this;
};

Server.prototype._emitCloseIfDrained = function() {
  if (this._handle || this._connections) {
    return;
  }

  process.nextTick(emitCloseNT, this);
};


function emitCloseNT(self) {
  self.emit('close');
}


Server.prototype.listenFD = function(fd, type) {
  return this.listen({ fd: fd });
};

Server.prototype._setupSlave = function(socketList) {
  this._usingSlaves = true;
  this._slaves.push(socketList);
};

Server.prototype.ref = function() {
  this._unref = false;

  if (this._handle)
    this._handle.ref();

  return this;
};

Server.prototype.unref = function() {
  this._unref = true;

  if (this._handle)
    this._handle.unref();

  return this;
};


// IPv4 Segment
const v4Seg = '(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])';
const v4Str = `(${v4Seg}[.]){3}${v4Seg}`;
const IPv4Reg = new RegExp(`^${v4Str}$`);

// IPv6 Segment
const v6Seg = '(?:[0-9a-fA-F]{1,4})';
const IPv6Reg = new RegExp('^(' +
  `(?:${v6Seg}:){7}(?:${v6Seg}|:)|` +
  `(?:${v6Seg}:){6}(?:${v4Str}|:${v6Seg}|:)|` +
  `(?:${v6Seg}:){5}(?::${v4Str}|(:${v6Seg}){1,2}|:)|` +
  `(?:${v6Seg}:){4}(?:(:${v6Seg}){0,1}:${v4Str}|(:${v6Seg}){1,3}|:)|` +
  `(?:${v6Seg}:){3}(?:(:${v6Seg}){0,2}:${v4Str}|(:${v6Seg}){1,4}|:)|` +
  `(?:${v6Seg}:){2}(?:(:${v6Seg}){0,3}:${v4Str}|(:${v6Seg}){1,5}|:)|` +
  `(?:${v6Seg}:){1}(?:(:${v6Seg}){0,4}:${v4Str}|(:${v6Seg}){1,6}|:)|` +
  `(?::((?::${v6Seg}){0,5}:${v4Str}|(?::${v6Seg}){1,7}|:))` +
')(%[0-9a-zA-Z-.:]{1,})?$');

function isIPv4(s) {
  return IPv4Reg.test(s);
}

function isIPv6(s) {
  return IPv6Reg.test(s);
}

function isIP(s) {
  if (isIPv4(s)) return 4;
  if (isIPv6(s)) return 6;
  return 0;
}


function _setSimultaneousAccepts(handle) {}


// Check that the port number is not NaN when coerced to a number,
// is an integer and that it falls within the legal range of port numbers.
function isLegalPort(port) {
  if ((typeof port !== 'number' && typeof port !== 'string') ||
      (typeof port === 'string' && port.trim().length === 0))
    return false;
  return +port === (+port >>> 0) && port <= 0xFFFF;
}


function assertPort(port) {
  if (typeof port !== 'undefined' && !isLegalPort(port))
    throw new RangeError('"port" argument must be >= 0 and < 65536');
}


function errnoException(err, syscall, original) {
  var errname = err.message;
  var message = syscall + ' ' + errname;
  if (original)
    message += ' ' + original;
  var e = new Error(message);
  e.code = errname;
  e.errno = errname;
  e.syscall = syscall;
  return e;
}


function exceptionWithHostPort(err,
                               syscall,
                               address,
                               port,
                               additional) {
  var details;
  if (port && port > 0) {
    details = address + ':' + port;
  } else {
    details = address;
  }

  if (additional) {
    details += ' - Local (' + additional + ')';
  }
  var ex = errnoException(err, syscall, details);
  ex.address = address;
  if (port) {
    ex.port = port;
  }
  return ex;
}
