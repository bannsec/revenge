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


function telescope(v, telescope_depth, type_hint, mem_range) {
    
    if ( telescope_depth === undefined ) {
        telescope_depth = 0;
    } else {
        telescope_depth += 1;
    }

    var scope = {
        "thing": v,
        "next": null,
        "mem_range": null,
        "telescope": true,
    };
    var v_type = telescope_get_type(v);
    scope.type = v_type;
    
    // Only telescoping on ints
    if ( v_type != "int" ) return scope;

    var ptr_v = ptr(v);
    
    // If we've hit our max depth, return
    if ( telescope_depth >= 3 ) return scope;

    // Use mem_range we're given or find it ourselves
    if ( mem_range ) {
        scope.mem_range = mem_range;
    } else {
        
        if ( ptr_v.compare(ptr("0xffffff")) < 0 ) {
            // Assume this isn't a valid range
            scope.mem_range = null;
        } else {
            scope.mem_range = Process.findRangeByAddress(ptr_v);
        }
    }
    
    // Doesn't point anywhere else, we're done
    if ( scope.mem_range === null ) return scope;


    // If this points to readable memory
    if ( scope.mem_range.protection[0] === "r" && type_hint !== "instruction") {

        // Try to telescope it as another pointer
        var mem_next = ptr_v.readPointer();
        var mem_next_range = Process.findRangeByAddress(mem_next);

        // If this is a valid pointer, recurse down into it
        if ( mem_next_range !== null ) {
            scope.next = telescope(mem_next, telescope_depth, null, mem_next_range);
            return scope;
        }

        // Is it a string?
        try {
            var as_str = ptr_v.readUtf8String();

            if ( as_str.length > 2 ) {
                scope.next = telescope(as_str, telescope_depth, null);
                // Keep int in case we messed up..
                scope.next["int"] = ptr_v.readPointer();
                return scope;
            }
        } catch (error) {}

    }

    // Address is an instruction?
    // Soemtimes Instruction.parse throws exception
    try {
        if ( scope.mem_range.protection[2] === "x" ) {
            scope.next = {
                "type": "instruction",
                "thing": Instruction.parse(ptr_v),
                "telescope": true,
                "next": null,
                "mem_range": null,
            };
            return scope;
        }
    } catch (e) {}

    // This is probably a pointer to some number...
    scope.next = telescope(ptr_v.readPointer(), telescope_depth, null);
    return scope;
}
