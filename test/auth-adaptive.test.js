import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeService, publicURL } from '../auth/browser/config.js';

test('adaptive enrollment requires no selectors and rejects private discovery destinations',()=>{
  const source={id:'catalog-item',origins:['https://example.com'],startUrl:'https://example.com/',authentication:{mode:'adaptive'}};
  const normalized=normalizeService(source);
  assert.deepEqual(normalized.flows,[]);
  assert.equal(normalized.adaptive.method,'password');
  for(const url of ['http://example.com','https://localhost/','https://localhost./','https://x.local/','https://127.0.0.1/','https://10.2.3.4/','https://172.20.1.1/','https://192.168.1.1/','https://[::1]/','https://[fc00::1]/','https://user:secret@example.com/'])assert.throws(()=>publicURL(url),{code:'ORIGIN_NOT_ALLOWED'},url);
  assert.equal(publicURL('https://example.com/signin?mode=login').origin,'https://example.com');
  assert.equal(publicURL('http://localhost:9876/',{allowLoopbackHttp:true}).hostname,'localhost');
  assert.throws(()=>normalizeService({...source,authentication:{mode:'adaptive',method:'script'}}),{code:'INVALID_SERVICE'});
  assert.throws(()=>normalizeService({...source,authentication:{mode:'adaptive',flows:[{}]}}),{code:'INVALID_SERVICE'});
  assert.throws(()=>normalizeService({...source,authentication:{mode:'adaptive',verification:{selector:'a',value:'account',attribute:'href'}}}),{code:'INVALID_SERVICE'});
});
