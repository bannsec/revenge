/* 
 * Include for allowing telescoping variables
 */

function telescope_get_type(thing) {
    
    if ( typeof(thing) === "number" ) {
        if ( thing % 1 === 0 ) return "int";
        return "float";
    }

    if ( typeof(thing) === "object" ) {
        if ( typeof(thing.writePointer) === "function" || typeof(thing.shr) === "function" ) return "int";
        return "unknown";
    }

    return typeof(thing);
}


function telescope(v) {
    var scope = {
        "thing": v,
        "next": null,
        "mem_range": null,
        "telescope": true,
    };
    var v_type = telescope_get_type(v);
    scope["type"] = v_type
    
    // Only telescoping on ints
    if ( v_type != "int" ) return scope;

    scope["mem_range"] = Process.findRangeByAddress(ptr(v));
    
    // Doesn't point anywhere else, we're done
    if ( scope["mem_range"] === null ) return scope;


    // If this points to readable memory
    if ( scope["mem_range"].protection[0] === "r" ) {

        // Try to telescope it as another pointer
        var mem_next = ptr(v).readPointer();
        var mem_next_range = Process.findRangeByAddress(mem_next)

        // If this is a valid pointer, recurse down into it
        if ( mem_next_range !== null ) {
            scope["next"] = telescope(mem_next);
            return scope;
        }

        // Is it a string?
        try {
            var as_str = ptr(v).readUtf8String()

            if ( as_str.length > 2 ) {
                scope["next"] = telescope(as_str)
                // Keep int in case we messed up..
                scope["next"]["int"] = ptr(v).readPointer()
                return scope;
            }
        } catch (error) {};

    }

    // Address is an instruction?
    if ( scope["mem_range"].protection[2] === "x" ) {
        scope["next"] = {
            "type": "instruction",
            "thing": Instruction.parse(ptr(v)),
            "telescope": true,
            "next": null,
            "mem_range": null,
        }
        return scope;
    }

    // This is probably a pointer to some number...
    scope["next"] = telescope(ptr(v).readPointer());
    return scope;
}
