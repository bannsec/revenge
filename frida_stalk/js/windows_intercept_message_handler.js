
var offset = OFFSET_HERE
var module = Process.getModuleByName("MODULE_HERE")
var handler = module.name + ":" + offset.toString(16)

Interceptor.attach(ptr(Number(module.base) + offset), {
    onEnter: function (args) {
        send([args[0], args[1], args[2], args[3], handler]);
    },

    onLeave: function (retval) {}
});
