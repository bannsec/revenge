
// Replace a given function with a loop that waits for a value to be true before going back to the function

var return_value = FUNCTION_RETURN_VALUE_HERE;
var func_ptr = FUNCTION_ADDRESS_HERE;

Interceptor.replace(func_ptr, new NativeCallback(function () {
    return return_value;
}, 'pointer', []));

