
// Replace a given function with a loop that waits for a value to be true before going back to the function

//var return_value = FUNCTION_RETURN_VALUE;
var func_ptr = FUNCTION_ADDRESS;

// Keep copy of original, just in case
var original = new NativeFunction(func_ptr, "FUNCTION_RETURN_TYPE", FUNCTION_ARG_TYPES);

Interceptor.replace(func_ptr, new NativeCallback(FUNCTION_REPLACE, "FUNCTION_RETURN_TYPE", FUNCTION_ARG_TYPES));

/*
Interceptor.replace(func_ptr, new NativeCallback(function () {
    return return_value;
}, return_type, []));
*/


