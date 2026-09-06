import config from './config.js';
import { startSender, startReceiver } from './runtime.js';

if (config && ['sender', 'receiver'].includes(config.role)) {
  const port = chrome.runtime.connectNative(config.nativeHostName);
  (config.role === 'sender' ? startSender : startReceiver)(chrome, port, config);
}
