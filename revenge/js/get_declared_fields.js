
var fields = Java.use('FULL_CLASS_HERE').class.getDeclaredFields();

fields.forEach(function (field) {

    send({
        'full_description': field.toString(),
        'name': field.getName(),
        'class': field.getType().toString(),
    })

});
