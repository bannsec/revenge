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

// Caches memory pages for performance
function telescope_get_memory_range(p) {

    if ( telescope_get_memory_range.ranges === undefined ) {
        telescope_get_memory_range.ranges = Process.enumerateRangesSync("---");
    }

    var mem_ranges = telescope_get_memory_range.ranges;

    for ( var i = 0; i < mem_ranges.length; i++ ) {
        var mem_range = mem_ranges[i];

        if ( mem_range.base.compare(p) <= 0 && mem_range.base.add(mem_range.size).compare(p) >= 0 ) {
            return mem_range;
        }
    }
    
    return null;
}

function telescope(v, telescope_depth, type_hint) {

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

    // Return data as ptr
    scope.thing = ptr(scope.thing);

    var ptr_v = ptr(v);
    
    // If we've hit our max depth, return
    if ( telescope_depth >= 3 ) return scope;

    // Option to disable it since it's so darn slow
    if ( telescope.mem_range_disabled ) {
        scope.mem_range = null;
    } else {
        // Setup mem_range
        if ( ptr_v.compare(ptr("0xffffff")) < 0 ) {
            // Assume this isn't a valid range
            scope.mem_range = null;
        } else {
            scope.mem_range = telescope_get_memory_range(ptr_v);
            //scope.mem_range = Process.findRangeByAddress(ptr_v);
        } 
    }
    
    // Doesn't point anywhere else, we're done
    //if ( scope.mem_range === null ) return scope;

    // If this points to readable memory
    if ( type_hint !== "instruction") {

        try {
            // Try to telescope it as another pointer
            var mem_next = ptr_v.readPointer();
            // This is a little implicit test to determine if it's a pointer to
            // a pointer. This will except out if it's not a pointer to a
            // pointer.
            mem_next.readPointer();
            scope.next = telescope(mem_next, telescope_depth, null, null);
            return scope;
        } catch (e) {}

        // Is it a string?
        try {
            var as_str = ptr_v.readUtf8String();

            if ( as_str.length > 2 ) {
                scope.next = telescope(as_str, telescope_depth, null);
                // Keep int in case we messed up..
                scope.next.int = ptr_v.readPointer();
                return scope;
            }
        } catch (error) {}


    }

    // Address is an instruction?
    // Soemtimes Instruction.parse throws exception
    try {
        if ( type_hint == "instruction" || scope.mem_range !== null && scope.mem_range.protection[2] === "x" ) {
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
    try {
        scope.next = telescope(ptr_v.readPointer(), telescope_depth, null);
        return scope;
    } catch (e) {};

    // *shrug*
    return scope;
}
