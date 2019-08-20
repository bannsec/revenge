
var func_ptr = ptr("FUNCTION_ADDRESS_HERE");

send("Setting pause at: " + func_ptr)
Interceptor.attach(func_ptr, {onEnter: function (args) { while ( 1 ) { Thread.sleep(1); }}});
