'use strict';

const co = require('co');
const EventEmitter = require('events');
const stream = require('stream');

module.exports = {
  connect: connect,
  createConnection: connect,
  createServer: createServer,
};

class NodeSocket extends stream.Duplex {
  constructor (options = {}) {
    super({});

    const {connection = null} = options;

    this.connecting = false;
    this.destroyed = false;
    this.bufferSize = 0;
    this.bytesRead = 0;
    this.bytesWritten = 0;
    this.readyState = (connection !== null) ? 'open' : 'closed';

    this._connection = connection;
    this._paused = true;
    this._connectRequest = null;
    this._closeRequest = null;
    this._readRequest = null;
    this._writeRequest = null;

    const destroy = () => this.destroy();
    this.on('end', destroy);
    this.on('finish', destroy);
  }

  ref () {
  }

  unref () {
  }

  connect (...args) {
    let options, connectListener;

    const firstArgType = typeof args[0];
    if (firstArgType === 'number') {
      const [port, host = 'localhost', listener = null] = args;
      options = {
        host: host,
        port: port,
      };
      connectListener = listener;
    } else if (firstArgType === 'string') {
      const [path, listener = null] = args;
      options = {
        path: path
      };
      connectListener = listener;
    } else {
      [options, connectListener] = args;
    }

    if (connectListener !== null) {
      this.once('connect', connectListener);
    }

    this._connectRequest = co(function* () {
      this.connecting = true;
      this.readyState = 'opening';

      const connection = yield Socket.connect(options);
      this._connection = connection;
      this._connectRequest = null;

      this.connecting = false;
      this.readyState = 'open';
      this.emit('connect');

      this._tryRead();
      this._tryWrite();
    }.bind(this))
    .catch(error => {
      this._connectRequest = null;
      this.connecting = false;
      this.readyState = 'closed';

      this.emit('error', error);
      this.emit('close', true);
      this.push(null);
    });
  }

  destroy (exception = null) {
    if (this.destroyed) {
      return;
    }
    this.destroyed = true;
    this.close(_ => {
      if (exception !== null) {
        this.emit('error', exception);
      }
    });
  }

  close (callback = null) {
    if (this._closeRequest === null) {
      this._closeRequest = co(function* () {
        if (this._connectRequest !== null) {
          try {
            yield this._connectRequest;
          } catch (e) {
          }
        }

        if (this._connection !== null) {
          try {
            yield this._connection.close();
          } catch (e) {
          }
          this._connection = null;
        }
      }.bind(this))
      .catch(error => {
        this.emit('error', error);
      });
    }

    if (callback !== null) {
      this._closeRequest
      .then(() => callback())
      .catch(error => callback(error));
    }
  }

  setKeepAlive (enable, initialDelay) {
    // TODO
  }

  setNoDelay (noDelay) {
    // TODO
  }

  setTimeout (timeout, callback) {
    // TODO
  }

  address () {
    // TODO
    return {
      port: 1234,
      family: 'IPv4',
      address: '127.0.0.1'
    };
  }

  _read (size) {
    this._paused = false;
    this._tryRead();
  }

  _write (chunk, encoding, callback) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    this._writeRequest = [value, callback];
    this._tryWrite();
  }

  _tryRead () {
    const connection = this._connection;
    if (connection === null || this._paused || this._readRequest !== null) {
      return;
    }

    this._readRequest = co(function* () {
      do {
        const buffer = yield connection.input.read(512);
        const size = buffer.byteLength;

        if (size === 0) {
          this.readyState = 'closed';
          this.emit('close', false);
          this.push(null);
          return;
        }

        this.bytesRead += size;

        if (!this.push(Buffer.from(buffer))) {
          this._paused = true;
        }
      } while (!this._paused);

      this._readRequest = null;
    }.bind(this))
    .catch(error => {
      this._readRequest = null;
      this._connection = null;
      this.destroyed = true;

      if (this._closeRequest === null) {
        this.emit('error', error);
        this.emit('close', true);
      } else {
        this.emit('close', false);
      }
      this.push(null);
    });
  }

  _tryWrite () {
    const connection = this._connection;
    if (connection === null || this._writeRequest === null) {
      return;
    }
    const [chunk, callback] = this._writeRequest;

    co(function* () {
      const size = yield connection.output.writeAll(chunk.buffer);

      this.bytesWritten += size;

      callback();
    }.bind(this))
    .catch(error => {
      callback(error);
    });
  }
}

class NodeServer extends EventEmitter {
  constructor (options) {
    super();

    this.listening = false;
    this.connections = 0;
    this.maxConnections = 0;

    this._listener = null;
    this._closing = false;
    this._closed = false;
    this._listenRequest = null;
  }

  ref () {
  }

  unref () {
  }

  listen (...args) {
    let options, callback;

    const firstArg = args[0];
    const firstArgType = typeof firstArg;
    if (firstArgType === 'string') {
      const [path, backlog = 511, cb = null] = args;
      if (cb !== null) {
        cb(new Error('Not yet supported'));
      }
      return;
    } else if (firstArgType === 'object') {
      if ('_handle' in firstArg || 'fd' in firstArg) {
        const [handle, backlog = 511, cb = null] = args;
        if (cb !== null) {
          cb(new Error('Not yet supported'));
        }
        return;
      } else {
        [options, callback = null] = args;
      }
    } else {
      const [port = 0, host = undefined, backlog = 511, cb = null] = args;
      options = {
        host: host,
        port: port,
        backlog: backlog,
      };
      callback = cb;
    }

    if (callback !== null) {
      this.once('listening', callback);
    }

    const start = () => {
      this._listenRequest = Socket.listen(options)
      .then(listener => {
        this._listener = listener;
        this._listenRequest = null;
        this.listening = true;
        this.emit('listening');

        return co(function* () {
          while (true) {
            const client = yield listener.accept();
            const socket = new NodeSocket({
              connection: client
            });
            this.connections++;
            socket.once('end', _ => {
              if (--this.connections === 0 && this._closing) {
                this.emit('close');
              }
            });
            this.emit('connection', socket);
          }
        }.bind(this));
      })
      .catch(error => {
        this._listener = null;
        this._listenRequest = null;
        const wasListening = this.listening;
        this.listening = false;

        this.emit('error', error);
        if (wasListening && this.connections === 0 && this._closing) {
          this.emit('close');
        }
      });
    }

    if (this._listenRequest !== null) {
      this._listenRequest.then(start, start);
    } else if (this._listener !== null) {
      this._listener.close().then(start, start);
    } else {
      start();
    }
  }

  close (callback = null) {
    if (this._closed) {
      if (callback !== null) {
        callback(new Error('Already closed'));
      }
      return;
    }

    if (callback !== null) {
      this.once('close', callback);
    }

    this._closing = true;

    co(function* () {
      if (this._listenRequest !== null) {
        try {
          yield this._listenRequest;
        } catch (e) {
        }
      }

      if (this._listener !== null) {
        try {
          yield this._listener.close();
        } catch (e) {
        }
        this._listener = null;
      }
    });
  }

  address () {
    if (this._listener === null) {
      return null;
    }

    return {
      port: this._listener.port,
      family: 'IPv4',
      address: '0.0.0.0',
    };
  }

  getConnections (callback) {
    callback(null, this.connections);
  }
}

function connect (...args) {
  const socket = new NodeSocket();
  socket.connect(...args);
  return socket;
}

function createServer (...args) {
  let options, connectionListener;

  const firstArgType = typeof args[0];
  if (firstArgType === 'function') {
    options = {};
    connectionListener = args[0];
  } else {
    [options = {}, connectionListener = null] = args;
  }

  const server = new NodeServer(options);
  if (connectionListener !== null) {
    server.on('connection', connectionListener);
  }
  return server;
}
