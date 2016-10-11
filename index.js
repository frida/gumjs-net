'use strict';

const co = require('co');
const EventEmitter = require('events');
const stream = require('stream');

module.exports = {
  connect: connect,
  createConnection: connect,
};

class NodeSocket extends stream.Duplex {
  constructor () {
    super({});

    this.connecting = false;
    this.destroyed = false;
    this.bufferSize = 0;
    this.bytesRead = 0;
    this.bytesWritten = 0;
    this.readyState = 'closed';

    this._connection = null;
    this._paused = true;
    this._connectRequest = null;
    this._closeRequest = null;
    this._readRequest = null;
    this._writeRequest = null;

    this.on('end', this.destroy.bind(this));
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
      })
      .then(() => {
        this.emit('close');
      })
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

      this.emit('error', error);
      this.emit('close', true);
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

function connect(...args) {
  const socket = new NodeSocket();
  socket.connect(...args);
  return socket;
}
