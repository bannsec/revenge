
/*
var libc_start_main = Module.getExportByName(null, '__libc_start_main')

Interceptor.attach(libc_start_main, {onLeave: function (args) {
    send("Leaving main");
    sleep(10);
},
    onEntry: function (args) {
        send("At main");
    },

});
*/

//var exit_func = Module.getExportByName(null, '_exit');
//Interceptor.attach(exit_func, {onEnter: function (args) { while ( 1 ) { Thread.sleep(1); }}})

var functions = ['exit', '_exit'];

functions.forEach(function x(item) { 
    var func = Module.getExportByName(null, item);
    send(item);

    if ( func != null ) {
        Interceptor.attach(func, {onEnter: function (args) { while ( 1 ) { Thread.sleep(1); }}});
    }
});
