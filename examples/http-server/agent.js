const Koa = require('koa');
const Router = require('koa-router');

const app = new Koa();
const router = new Router();

router
  .get('/ranges', (ctx, next) => {
    ctx.body = Process.enumerateRanges({
      protection: '---',
      coalesce: true
    });
  })
  .get('/modules', (ctx, next) => {
    ctx.body = Process.enumerateModules();
  })
  .get('/modules/:name', (ctx, next) => {
    try {
      ctx.body = Process.getModuleByName(ctx.params.name);
    } catch (e) {
      ctx.status = 404;
      ctx.body = e.message;
    }
  })
  .get('/modules/:name/exports', (ctx, next) => {
    ctx.body = Module.enumerateExports(ctx.params.name);
  })
  .get('/modules/:name/imports', (ctx, next) => {
    ctx.body = Module.enumerateImports(ctx.params.name);
  })
  .get('/objc/classes', (ctx, next) => {
    if (ObjC.available) {
      ctx.body = Object.keys(ObjC.classes);
    } else {
      ctx.status = 404;
      ctx.body = 'Objective-C runtime not available in this process';
    }
  })
  .get('/threads', (ctx, next) => {
    ctx.body = Process.enumerateThreads();
  });

app
  .use(router.routes())
  .use(router.allowedMethods())
  .listen(1337);
