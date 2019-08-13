const irc = require('irc');

const server = 'irc.freenode.net';
const channel = '#frida';
const nick = 'Inside' + Process.enumerateModules()[0].name;

const client = new irc.Client(server, nick, {
  channels: [channel],
});
client.on('connect', _ => {
  client.conn.setNoDelay(true);
});
client.on('error', error => {
  console.log('*** ERROR: ' + JSON.stringify(error, null, 2));
});
client.on('message' + channel, (from, message) => {
  const trigger = client.nick + ': ';
  if (message.indexOf(trigger) === -1)
    return;
  const code = message.substr(trigger.length);

  let result;
  try {
    const rawResult = (1, eval)(code);
    global._ = rawResult;
    result = JSON.stringify(rawResult);
  } catch (e) {
    result = 'throw new ' + e.name + '("' + e.message + '")';
  }

  client.say(channel, `${from}: ${result}`);
});
