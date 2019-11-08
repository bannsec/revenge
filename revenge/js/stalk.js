
/* 
 * Basic stalker
 *
 * requires: dispose.js, batch_send.js
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

function stalker_is_in_include_function(include_function, event) {
    var ip = include_function;
    var type = event[0];
    var inside = stalker_is_in_include_function.inside || false;
    var inside_depth_floor = stalker_is_in_include_function.inside_depth_floor;

    if ( type == 'call' ) {
        var call_target = ptr(event[2]);

        // We're stepping into this function
        if ( ! inside && call_target.compare(ip) == 0 ) {
            stalker_is_in_include_function.inside = true;
            stalker_is_in_include_function.inside_depth_floor = Number(event[3]);
        }
    } else if ( type == 'ret' ) {
        var current_depth = Number(event[3]);

        // If we're inside and about to step out
        if ( inside && current_depth == inside_depth_floor + 1 ) {
            // Set outside, but still return this as being inside
            stalker_is_in_include_function.inside = false;
        }
    }

    return inside;
}

// This function handles implicitly adding event depth based on previous depths
function event_get_depth(event) {
    var depth = event_get_depth.depth || 0;

    if ( event[0] == 'call' ) {
        depth = Number(event[3]) + 1;
        event_get_depth.depth = depth;

    } else if ( event[0] == 'ret' ) {
        depth = Number(event[3]) - 1;
        event_get_depth.depth = depth;
    }

    return event_get_depth.depth;
}

function stalker_follow(tid) {
    var module_map = new ModuleMap();
    var include_from = FROM_MODULES_HERE;
    var include_function = INCLUDE_FUNCTION_HERE;
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
    
    Stalker.follow(tid, {
        events: {
            call: STALK_CALL || include_function !== null,  // CALL instructions
            ret: STALK_RET || include_function !== null,    // RET instructions
            exec: STALK_EXEC,                               // all instructions: not recommended as it's a lot of data
            block: STALK_BLOCK,                             // block executed: coarse execution trace
            compile: STALK_COMPILE                          // block compiled: useful for coverage
        },

        onReceive: function (events) {

            var filtered_events = [];

            Stalker.parse(events, {annotate: true, stringify: true}).forEach(function x(event) { 

                var depth = event_get_depth(event);

                // Handle include function
                if ( include_function !== null && ! stalker_is_in_include_function(include_function, event) ) {
                    return;
                }

                // Handle exclude ranges
                if ( stalker_is_in_range(exclude_ranges, ptr(event[1]))) {
                    return;
                }
                
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

                var event_dict = {};

                if ( event[0] == 'call' ) {

                    event_dict.tid          = tid;
                    event_dict.type         = 'call';
                    event_dict.from_ip      = event[1];
                    event_dict.to_ip        = event[2];
                    event_dict.depth        = Number(event[3]);
                    event_dict.from_module  = from_module;
                    event_dict.to_module    = module_map.findName(ptr(event[2]));
                    
                } else if ( event[0] == 'ret' ) {
                    
                    event_dict.tid          = tid;
                    event_dict.type         = 'ret';
                    event_dict.from_ip      = event[1];
                    event_dict.to_ip        = event[2];
                    event_dict.depth        = Number(event[3]);
                    event_dict.from_module  = from_module;
                    event_dict.to_module    = module_map.findName(ptr(event[2]));

                } else if ( event[0] == 'exec' ) {
                    
                    event_dict.tid          = tid;
                    event_dict.type         = 'exec';
                    event_dict.from_ip      = event[1];
                    event_dict.from_module  = from_module;
                    event_dict.depth        = depth;

                } else if ( event[0] == 'block' ) {

                    event_dict.tid          = tid;
                    event_dict.type         = 'block';
                    event_dict.from_ip      = event[1];
                    event_dict.to_ip        = event[2];
                    event_dict.from_module  = from_module;
                    event_dict.to_module    = module_map.findName(ptr(event[2]));
                    event_dict.depth        = depth;
                    
                } else if ( event[0] == 'compile' ) {

                    event_dict.tid          = tid;
                    event_dict.type         = 'compile';
                    event_dict.from_ip      = event[1];
                    event_dict.to_ip        = event[2];
                    event_dict.from_module  = from_module;
                    event_dict.to_module    = module_map.findName(ptr(event[2]));
                    event_dict.depth        = depth;

                }

                filtered_events.push(event_dict);
            });

            if ( filtered_events.length != 0 ) {
                send_batch(filtered_events);
                //send(filtered_events);
            }
        }
    })
}

