const app = require('koa')();
const router = require('koa-router')();

router
  .get('/ranges', function *(next) {
    this.body = Process.enumerateRangesSync({
      protection: '---',
      coalesce: true
    });
  })
  .get('/modules', function *(next) {
    this.body = Process.enumerateModulesSync();
  })
  .get('/modules/:name', function *(next) {
    try {
      this.body = Process.getModuleByName(this.params.name);
    } catch (e) {
      this.status = 404;
      this.body = e.message;
    }
  })
  .get('/modules/:name/exports', function *(next) {
    this.body = Module.enumerateExportsSync(this.params.name);
  })
  .get('/modules/:name/imports', function *(next) {
    this.body = Module.enumerateImportsSync(this.params.name);
  })
  .get('/objc/classes', function *(next) {
    if (ObjC.available) {
      this.body = Object.keys(ObjC.classes);
    } else {
      this.status = 404;
      this.body = 'Objective-C runtime not available in this process';
    }
  })
  .get('/threads', function *(next) {
    this.body = Process.enumerateThreadsSync();
  });

app
  .use(router.routes())
  .use(router.allowedMethods())
  .listen(1337);
