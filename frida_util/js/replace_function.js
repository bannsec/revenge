
// Replace a given function with a loop that waits for a value to be true before going back to the function

var symbol = "FUNCTION_SYMBOL_HERE";
var module = "FUNCTION_MODULE_HERE";
var offset = FUNCTION_OFFSET_HERE;
var return_value = ptr(FUNCTION_RETURN_VALUE_HERE);

if ( module == "" ) {
    module = null;
}

if ( symbol != "" ) {
    var func_ptr = Module.getExportByName(module, symbol);
} else {
    var func_ptr = ptr(Number(Module.getBaseAddress(module)) + offset)
}

Interceptor.replace(func_ptr, new NativeCallback(function () {
    return return_value;
}, 'pointer', []));

