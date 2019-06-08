var functions = PAUSE_AT_ARRAY_HERE;

functions.forEach(function x(item) { 
    var func = Module.getExportByName(null, item);
    send(item);

    if ( func != null ) {
        Interceptor.attach(func, {onEnter: function (args) { while ( 1 ) { Thread.sleep(1); }}});
    }
});
