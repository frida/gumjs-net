'use strict';

const nsq = require('nsq.js');

const writer = nsq.writer(':4150');
writer.on('error', error => {
  console.log('*** ERROR: ' + error.stack);
});
writer.on('ready', () => {
  Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter(args) {
      const path = Memory.readUtf8String(args[0]);
      writer.publish('frida', {
        name: 'open',
        path: path
      });
    }
  });
});
