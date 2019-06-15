
// Replace a given function with a loop that waits for a value to be true before going back to the function

var return_value = FUNCTION_RETURN_VALUE;
var return_type = "FUNCTION_RETURN_TYPE";
var func_ptr = FUNCTION_ADDRESS;

Interceptor.replace(func_ptr, new NativeCallback(function () {
    return return_value;
}, return_type, []));

