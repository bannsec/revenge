
/* instruction_count.js
 *
 * Simply figure out how many instructions get executed
 *
 * requires: dispose.js, send_repeat.js
 */

function stalker_is_in_range(ranges, val) {
    var range;
    for (var i=0; i < ranges.length; i++) {
        range = ranges[i];
        if ( val >= range[0]  && val <= range[1] )
            return true;
    }
    return false;
}

function instruction_count(tid) {
    var module_map = new ModuleMap();
    var include_from = FROM_MODULES_HERE;
    var exclude_ranges = Array();
    var count = {"count": 0, "tid": tid};
    var exclude_ranges = Array();

    EXCLUDE_RANGES_HERE.forEach(function (item) {
        exclude_ranges.push(Array( eval(item[0]), eval(item[1])));
    });

    // Unfollow must be called from the source script doing the stalking. Thus, RPC.
    rpc.exports.unfollow = function () {
            Stalker.unfollow(tid);
            Stalker.flush();
    };

    // This is automagically called when unloading a script in python
    dispose_push( function () { Stalker.unfollow(tid); } );

    // TODO: What should this actually be?
    // also, lower this back down when Stalker starts draining properly again
    Stalker.queueCapacity = 1048576; // 32768; //65536;
    //Stalker.queueDrainInterval = 10;

    // Start sending our count back
    send_repeat(count);
    
    Stalker.follow(tid, {
        events: {
            call: STALK_CALL,          // CALL instructions
            ret: STALK_RET,            // RET instructions
            exec: STALK_EXEC,          // all instructions
            block: STALK_BLOCK,        // block executed: coarse execution trace
            compile: STALK_COMPILE     // block compiled: useful for coverage
        },

        onReceive: function (events) {

            var filtered_events = [];

            Stalker.parse(events, {annotate: true, stringify: true}).forEach(function x(event) { 

                //
                // Module filtering
                //

                var from_module = module_map.findName(ptr(event[1]));

                if ( from_module != null ) {

                    // Ignore frida agent calls
                    if ( from_module.substring(0, 11) == "frida-agent" ) {
                        return;
                    }

                    // Optionally only include from some modules
                    if (include_from.length > 0 && !include_from.includes(from_module)) {
                        return;
                    }

                }

                // Handle exclude ranges
                // TODO: Would it be more efficient to check first before making the function call?
                if ( stalker_is_in_range(exclude_ranges, ptr(event[1]))) {
                    return;
                }

                count.count += 1;
            });
        }
    })
}

