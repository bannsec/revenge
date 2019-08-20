
var methods = Java.use('FULL_CLASS_HERE').class.getDeclaredMethods();

methods.forEach(function (method) {

    send({
        'full_description': method.toString(),
        'name': method.getName(),
        'return_type': method.getReturnType().toString(),
    })

});
