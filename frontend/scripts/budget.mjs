import {readdir,readFile} from 'node:fs/promises';import {gzipSync} from 'node:zlib';
let size=0,gzip=0;for(const file of await readdir('dist/assets')){const b=await readFile('dist/assets/'+file);size+=b.length;gzip+=gzipSync(b).length;}if(size>350000||gzip>100000)throw new Error('UI bundle budget exceeded');console.log(`UI assets: ${size} bytes; gzip: ${gzip} bytes (budgets 350000 / 100000)`);
